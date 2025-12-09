use super::*;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RollingConditionBase {
    last_write_opt: Option<DateTime<Local>>,
    frequency_opt: Option<RollingFrequency>,
    max_size_opt: Option<u64>,
}

impl RollingConditionBase {
    /// Constructs a new struct that does not yet have any condition set.
    pub fn new() -> RollingConditionBase {
        RollingConditionBase {
            last_write_opt: None,
            frequency_opt: None,
            max_size_opt: None,
        }
    }

    /// Sets a condition to rollover on the given frequency
    pub fn frequency(mut self, x: RollingFrequency) -> RollingConditionBase {
        self.frequency_opt = Some(x);
        self
    }

    /// Sets a condition to rollover when the date changes
    pub fn daily(mut self) -> RollingConditionBase {
        self.frequency_opt = Some(RollingFrequency::EveryDay);
        self
    }

    /// Sets a condition to rollover when the date or hour changes
    pub fn hourly(mut self) -> RollingConditionBase {
        self.frequency_opt = Some(RollingFrequency::EveryHour);
        self
    }

    /// Sets a condition to rollover when the date or minute changes
    pub fn minutely(mut self) -> RollingConditionBase {
        self.frequency_opt = Some(RollingFrequency::EveryMinute);
        self
    }

    /// Sets a condition to rollover when a certain size is reached
    pub fn max_size(mut self, x: u64) -> RollingConditionBase {
        self.max_size_opt = Some(x);
        self
    }
}

impl Default for RollingConditionBase {
    fn default() -> Self {
        RollingConditionBase::new().frequency(RollingFrequency::EveryDay)
    }
}

impl RollingCondition for RollingConditionBase {
    fn should_rollover(&mut self, now: &DateTime<Local>, current_filesize: u64) -> bool {
        let mut rollover = false;
        if let Some(frequency) = self.frequency_opt.as_ref() {
            if let Some(last_write) = self.last_write_opt.as_ref() {
                if frequency.equivalent_datetime(now) != frequency.equivalent_datetime(last_write) {
                    rollover = true;
                }
            }
        }
        if let Some(max_size) = self.max_size_opt.as_ref() {
            if current_filesize >= *max_size {
                rollover = true;
            }
        }
        self.last_write_opt = Some(*now);
        rollover
    }
}

pub struct RollingFileAppenderBaseBuilder {
    condition: RollingConditionBase,
    filename: String,
    max_filecount: usize,
    current_filesize: u64,
    writer_opt: Option<BufWriter<File>>,
}

impl Default for RollingFileAppenderBaseBuilder {
    fn default() -> Self {
        RollingFileAppenderBaseBuilder {
            condition: RollingConditionBase::default(),
            filename: String::new(),
            max_filecount: 10,
            current_filesize: 0,
            writer_opt: None,
        }
    }
}

impl RollingFileAppenderBaseBuilder {
    /// Sets the log filename. Uses absolute path if provided, otherwise
    /// creates files in the current working directory.
    pub fn filename(mut self, filename: String) -> Self {
        self.filename = filename;
        self
    }

    /// Sets a condition for the maximum number of files to create before rolling
    /// over and deleting the oldest one.
    pub fn max_filecount(mut self, max_filecount: usize) -> Self {
        self.max_filecount = max_filecount;
        self
    }

    /// Sets a condition to rollover on a daily basis
    pub fn condition_daily(mut self) -> Self {
        self.condition.frequency_opt = Some(RollingFrequency::EveryDay);
        self
    }

    /// Sets a condition to rollover when the date or hour changes
    pub fn condition_hourly(mut self) -> Self {
        self.condition.frequency_opt = Some(RollingFrequency::EveryHour);
        self
    }

    /// Sets a condition to rollover when the date or minute changes
    pub fn condition_minutely(mut self) -> Self {
        self.condition.frequency_opt = Some(RollingFrequency::EveryMinute);
        self
    }

    /// Sets a condition to rollover when a certain size is reached
    pub fn condition_max_file_size(mut self, x: u64) -> Self {
        self.condition.max_size_opt = Some(x);
        self
    }

    /// Builds a RollingFileAppenderBase instance from the current settings.
    ///
    /// Returns an error if the filename is empty.
    pub fn build(self) -> Result<RollingFileAppenderBase, &'static str> {
        if self.filename.is_empty() {
            return Err("A filename is required to be set and can not be blank");
        }
        Ok(RollingFileAppenderBase {
            condition: self.condition,
            filename: self.filename,
            max_filecount: self.max_filecount,
            current_filesize: self.current_filesize,
            writer_opt: self.writer_opt,
        })
    }
}

impl RollingFileAppenderBase {
    /// Creates a new rolling file appender builder instance with the default
    /// settings without a filename set.
    pub fn builder() -> RollingFileAppenderBaseBuilder {
        RollingFileAppenderBaseBuilder::default()
    }
}

/// A rolling file appender with a rolling condition based on date/time or size.
pub type RollingFileAppenderBase = RollingFileAppender<RollingConditionBase>;

// LCOV_EXCL_START
#[cfg(test)]
mod test {
    use super::*;

    struct Context {
        _tempdir: tempfile::TempDir,
        rolling: RollingFileAppenderBase,
    }

    impl Context {
        fn verify_contains(&mut self, needle: &str, n: usize) {
            self.rolling.flush().unwrap();
            let p = self.rolling.filename_for(n);
            let haystack = fs::read_to_string(&p).unwrap();
            if !haystack.contains(needle) {
                panic!("file {:?} did not contain expected contents {}", p, needle);
            }
        }
    }

    fn build_context(condition: RollingConditionBase, max_files: usize) -> Context {
        let tempdir = tempfile::tempdir().unwrap();
        let filename = tempdir.path().join("test.log");
        let rolling = RollingFileAppenderBase::new(filename, condition, max_files).unwrap();
        Context {
            _tempdir: tempdir,
            rolling,
        }
    }

    fn build_builder_context(mut builder: RollingFileAppenderBaseBuilder) -> Context {
        if builder.filename.is_empty() {
            builder = builder.filename(String::from("test.log"));
        }
        let tempdir = tempfile::tempdir().unwrap();
        let filename = tempdir.path().join(&builder.filename);
        builder = builder.filename(String::from(filename.as_os_str().to_str().unwrap()));
        Context {
            _tempdir: tempdir,
            rolling: builder.build().unwrap(),
        }
    }

    #[test]
    fn frequency_every_day() {
        let mut c = build_context(RollingConditionBase::new().daily(), 9);
        c.rolling
            .write_with_datetime(
                b"Line 1\n",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 2, 3).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 2\n",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 3, 0).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 3\n",
                &Local.with_ymd_and_hms(2021, 3, 31, 1, 4, 0).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 4\n",
                &Local.with_ymd_and_hms(2021, 5, 31, 1, 4, 0).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 5\n",
                &Local.with_ymd_and_hms(2022, 5, 31, 1, 4, 0).unwrap(),
            )
            .unwrap();
        assert!(!AsRef::<Path>::as_ref(&c.rolling.filename_for(4)).exists());
        c.verify_contains("Line 1", 3);
        c.verify_contains("Line 2", 3);
        c.verify_contains("Line 3", 2);
        c.verify_contains("Line 4", 1);
        c.verify_contains("Line 5", 0);
    }

    #[test]
    fn frequency_every_day_limited_files() {
        let mut c = build_context(RollingConditionBase::new().daily(), 2);
        c.rolling
            .write_with_datetime(
                b"Line 1\n",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 2, 3).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 2\n",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 3, 0).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 3\n",
                &Local.with_ymd_and_hms(2021, 3, 31, 1, 4, 0).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 4\n",
                &Local.with_ymd_and_hms(2021, 5, 31, 1, 4, 0).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 5\n",
                &Local.with_ymd_and_hms(2022, 5, 31, 1, 4, 0).unwrap(),
            )
            .unwrap();
        assert!(!AsRef::<Path>::as_ref(&c.rolling.filename_for(4)).exists());
        assert!(!AsRef::<Path>::as_ref(&c.rolling.filename_for(3)).exists());
        c.verify_contains("Line 3", 2);
        c.verify_contains("Line 4", 1);
        c.verify_contains("Line 5", 0);
    }

    #[test]
    fn frequency_every_hour() {
        let mut c = build_context(RollingConditionBase::new().hourly(), 9);
        c.rolling
            .write_with_datetime(
                b"Line 1\n",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 2, 3).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 2\n",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 3, 2).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 3\n",
                &Local.with_ymd_and_hms(2021, 3, 30, 2, 1, 0).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 4\n",
                &Local.with_ymd_and_hms(2021, 3, 31, 2, 1, 0).unwrap(),
            )
            .unwrap();
        assert!(!AsRef::<Path>::as_ref(&c.rolling.filename_for(3)).exists());
        c.verify_contains("Line 1", 2);
        c.verify_contains("Line 2", 2);
        c.verify_contains("Line 3", 1);
        c.verify_contains("Line 4", 0);
    }

    #[test]
    fn frequency_every_minute() {
        let mut c = build_context(
            RollingConditionBase::new().frequency(RollingFrequency::EveryMinute),
            9,
        );
        c.rolling
            .write_with_datetime(
                b"Line 1\n",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 2, 3).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 2\n",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 2, 3).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 3\n",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 2, 4).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 4\n",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 3, 0).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 5\n",
                &Local.with_ymd_and_hms(2021, 3, 30, 2, 3, 0).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"Line 6\n",
                &Local.with_ymd_and_hms(2022, 3, 30, 2, 3, 0).unwrap(),
            )
            .unwrap();
        assert!(!AsRef::<Path>::as_ref(&c.rolling.filename_for(4)).exists());
        c.verify_contains("Line 1", 3);
        c.verify_contains("Line 2", 3);
        c.verify_contains("Line 3", 3);
        c.verify_contains("Line 4", 2);
        c.verify_contains("Line 5", 1);
        c.verify_contains("Line 6", 0);
    }

    #[test]
    fn max_size() {
        let mut c = build_context(RollingConditionBase::new().max_size(10), 9);
        c.rolling
            .write_with_datetime(
                b"12345",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 2, 3).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"6789",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 3, 3).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(b"0", &Local.with_ymd_and_hms(2021, 3, 30, 2, 3, 3).unwrap())
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"abcdefghijkl",
                &Local.with_ymd_and_hms(2021, 3, 31, 2, 3, 3).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"ZZZ",
                &Local.with_ymd_and_hms(2022, 3, 31, 1, 2, 3).unwrap(),
            )
            .unwrap();
        assert!(!AsRef::<Path>::as_ref(&c.rolling.filename_for(3)).exists());
        c.verify_contains("1234567890", 2);
        c.verify_contains("abcdefghijkl", 1);
        c.verify_contains("ZZZ", 0);
    }

    #[test]
    fn max_size_existing() {
        let mut c = build_context(RollingConditionBase::new().max_size(10), 9);
        c.rolling
            .write_with_datetime(
                b"12345",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 2, 3).unwrap(),
            )
            .unwrap();
        // close the file and make sure that it can re-open it, and that it
        // resets the file size properly.
        c.rolling.writer_opt.take();
        c.rolling.current_filesize = 0;
        c.rolling
            .write_with_datetime(
                b"6789",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 3, 3).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(b"0", &Local.with_ymd_and_hms(2021, 3, 30, 2, 3, 3).unwrap())
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"abcdefghijkl",
                &Local.with_ymd_and_hms(2021, 3, 31, 2, 3, 3).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"ZZZ",
                &Local.with_ymd_and_hms(2022, 3, 31, 1, 2, 3).unwrap(),
            )
            .unwrap();
        assert!(!AsRef::<Path>::as_ref(&c.rolling.filename_for(3)).exists());
        c.verify_contains("1234567890", 2);
        c.verify_contains("abcdefghijkl", 1);
        c.verify_contains("ZZZ", 0);
    }

    #[test]
    fn daily_and_max_size() {
        let mut c = build_context(RollingConditionBase::new().daily().max_size(10), 9);
        c.rolling
            .write_with_datetime(
                b"12345",
                &Local.with_ymd_and_hms(2021, 3, 30, 1, 2, 3).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"6789",
                &Local.with_ymd_and_hms(2021, 3, 30, 2, 3, 3).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(b"0", &Local.with_ymd_and_hms(2021, 3, 31, 2, 3, 3).unwrap())
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"abcdefghijkl",
                &Local.with_ymd_and_hms(2021, 3, 31, 3, 3, 3).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"ZZZ",
                &Local.with_ymd_and_hms(2021, 3, 31, 4, 4, 4).unwrap(),
            )
            .unwrap();
        assert!(!AsRef::<Path>::as_ref(&c.rolling.filename_for(3)).exists());
        c.verify_contains("123456789", 2);
        c.verify_contains("0abcdefghijkl", 1);
        c.verify_contains("ZZZ", 0);
    }

    #[test]
    fn rolling_file_appender_builder() {
        let builder = RollingFileAppender::builder();

        let builder = builder.condition_daily().condition_max_file_size(10);
        let mut c = build_builder_context(builder);
        c.rolling
            .write_with_datetime(
                b"abcdefghijklmnop",
                &Local.with_ymd_and_hms(2021, 3, 31, 4, 4, 4).unwrap(),
            )
            .unwrap();
        c.rolling
            .write_with_datetime(
                b"12345678",
                &Local.with_ymd_and_hms(2021, 3, 31, 5, 4, 4).unwrap(),
            )
            .unwrap();
        assert!(AsRef::<Path>::as_ref(&c.rolling.filename_for(1)).exists());
        assert!(Path::new(&c.rolling.filename_for(0)).exists());
        c.verify_contains("abcdefghijklmnop", 1);
        c.verify_contains("12345678", 0);
    }

    #[test]
    fn rolling_file_appender_builder_no_filename() {
        let builder = RollingFileAppender::builder();
        let appender = builder.condition_daily().build();
        assert!(appender.is_err());
    }
}
// LCOV_EXCL_STOP
