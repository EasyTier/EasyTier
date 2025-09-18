#![deny(warnings)]

use chrono::prelude::*;
use std::{
    convert::TryFrom,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    path::Path,
};

/// Determines when a file should be "rolled over".
pub trait RollingCondition {
    /// Determine and return whether or not the file should be rolled over.
    fn should_rollover(&mut self, now: &DateTime<Local>, current_filesize: u64) -> bool;
}

/// Determines how often a file should be rolled over
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RollingFrequency {
    EveryDay,
    EveryHour,
    EveryMinute,
}

impl RollingFrequency {
    /// Calculates a datetime that will be different if data should be in
    /// different files.
    pub fn equivalent_datetime(&self, dt: &DateTime<Local>) -> DateTime<Local> {
        let (year, month, day) = (dt.year(), dt.month(), dt.day());
        let (hour, min, sec) = match self {
            RollingFrequency::EveryDay => (0, 0, 0),
            RollingFrequency::EveryHour => (dt.hour(), 0, 0),
            RollingFrequency::EveryMinute => (dt.hour(), dt.minute(), 0),
        };
        Local
            .with_ymd_and_hms(year, month, day, hour, min, sec)
            .unwrap()
    }
}

/// Writes data to a file, and "rolls over" to preserve older data in
/// a separate set of files. Old files have a Debian-style naming scheme
/// where we have base_filename, base_filename.1, ..., base_filename.N
/// where N is the maximum number of rollover files to keep.
#[derive(Debug)]
pub struct RollingFileAppender<RC>
where
    RC: RollingCondition,
{
    condition: RC,
    filename: String,
    max_filecount: usize,
    current_filesize: u64,
    writer_opt: Option<BufWriter<File>>,
}

impl<RC> RollingFileAppender<RC>
where
    RC: RollingCondition,
{
    /// Creates a new rolling file appender with the given condition.
    /// The filename parent path must already exist.
    pub fn new(
        filename: impl AsRef<Path>,
        condition: RC,
        max_filecount: usize,
    ) -> io::Result<RollingFileAppender<RC>> {
        let filename = filename.as_ref().to_str().unwrap().to_string();
        let mut appender = RollingFileAppender {
            condition,
            filename,
            max_filecount,
            current_filesize: 0,
            writer_opt: None,
        };
        // Fail if we can't open the file initially...
        appender.open_writer_if_needed()?;
        Ok(appender)
    }

    /// Determines the final filename, where n==0 indicates the current file
    fn filename_for(&self, n: usize) -> String {
        let f = self.filename.clone();
        if n > 0 {
            format!("{}.{}", f, n)
        } else {
            f
        }
    }

    /// Rotates old files to make room for a new one.
    /// This may result in the deletion of the oldest file
    fn rotate_files(&mut self) -> io::Result<()> {
        // ignore any failure removing the oldest file (may not exist)
        let _ = fs::remove_file(self.filename_for(self.max_filecount.max(1)));
        let mut r = Ok(());
        for i in (0..self.max_filecount.max(1)).rev() {
            let rotate_from = self.filename_for(i);
            let rotate_to = self.filename_for(i + 1);
            if let Err(e) = fs::rename(&rotate_from, &rotate_to).or_else(|e| match e.kind() {
                io::ErrorKind::NotFound => Ok(()),
                _ => Err(e),
            }) {
                // capture the error, but continue the loop,
                // to maximize ability to rename everything
                r = Err(e);
            }
        }
        r
    }

    /// Forces a rollover to happen immediately.
    pub fn rollover(&mut self) -> io::Result<()> {
        // Before closing, make sure all data is flushed successfully.
        self.flush()?;
        // We must close the current file before rotating files
        self.writer_opt.take();
        self.current_filesize = 0;
        self.rotate_files()?;
        self.open_writer_if_needed()
    }

    /// Opens a writer for the current file.
    fn open_writer_if_needed(&mut self) -> io::Result<()> {
        if self.writer_opt.is_none() {
            let path = self.filename_for(0);
            let path = Path::new(&path);
            let mut open_options = OpenOptions::new();
            open_options.append(true).create(true);
            let new_file = match open_options.open(path) {
                Ok(new_file) => new_file,
                Err(err) => {
                    let Some(parent) = path.parent() else {
                        return Err(err);
                    };
                    fs::create_dir_all(parent)?;
                    open_options.open(path)?
                }
            };
            self.writer_opt = Some(BufWriter::new(new_file));
            self.current_filesize = path.metadata().map_or(0, |m| m.len());
        }
        Ok(())
    }

    /// Writes data using the given datetime to calculate the rolling condition
    pub fn write_with_datetime(&mut self, buf: &[u8], now: &DateTime<Local>) -> io::Result<usize> {
        if self.condition.should_rollover(now, self.current_filesize) {
            if let Err(e) = self.rollover() {
                // If we can't rollover, just try to continue writing anyway
                // (better than missing data).
                // This will likely used to implement logging, so
                // avoid using log::warn and log to stderr directly
                eprintln!("WARNING: Failed to rotate logfile {}: {}", self.filename, e);
            }
        }
        self.open_writer_if_needed()?;
        if let Some(writer) = self.writer_opt.as_mut() {
            let buf_len = buf.len();
            writer.write_all(buf).map(|_| {
                self.current_filesize += u64::try_from(buf_len).unwrap_or(u64::MAX);
                buf_len
            })
        } else {
            Err(io::Error::other("unexpected condition: writer is missing"))
        }
    }
}

impl<RC> io::Write for RollingFileAppender<RC>
where
    RC: RollingCondition,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let now = Local::now();
        self.write_with_datetime(buf, &now)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(writer) = self.writer_opt.as_mut() {
            writer.flush()?;
        }
        Ok(())
    }
}

pub struct FileAppenderWrapper {
    appender: std::sync::Arc<parking_lot::Mutex<RollingFileAppenderBase>>,
}

impl tracing_subscriber::fmt::MakeWriter<'_> for FileAppenderWrapper {
    type Writer = FileAppenderWriter;

    fn make_writer(&self) -> Self::Writer {
        FileAppenderWriter {
            appender: self.appender.clone(),
        }
    }
}

impl FileAppenderWrapper {
    pub fn new(appender: RollingFileAppenderBase) -> Self {
        Self {
            appender: std::sync::Arc::new(parking_lot::Mutex::new(appender)),
        }
    }
}

pub struct FileAppenderWriter {
    appender: std::sync::Arc<parking_lot::Mutex<RollingFileAppenderBase>>,
}

impl std::io::Write for FileAppenderWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.appender.lock().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.appender.lock().flush()
    }
}

pub mod base;
pub use base::*;
