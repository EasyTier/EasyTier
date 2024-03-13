use rkyv::{
    string::ArchivedString,
    validation::{validators::DefaultValidator, CheckTypeError},
    vec::ArchivedVec,
    Archive, CheckBytes, Serialize,
};
use tokio_util::bytes::{Bytes, BytesMut};

pub fn decode_from_bytes_checked<'a, T: Archive>(
    bytes: &'a [u8],
) -> Result<&'a T::Archived, CheckTypeError<T::Archived, DefaultValidator<'a>>>
where
    T::Archived: CheckBytes<DefaultValidator<'a>>,
{
    rkyv::check_archived_root::<T>(bytes)
}

pub fn decode_from_bytes<'a, T: Archive>(
    bytes: &'a [u8],
) -> Result<&'a T::Archived, CheckTypeError<T::Archived, DefaultValidator<'a>>>
where
    T::Archived: CheckBytes<DefaultValidator<'a>>,
{
    // rkyv::check_archived_root::<T>(bytes)
    unsafe { Ok(rkyv::archived_root::<T>(bytes)) }
}

// allow deseraial T to Bytes
pub fn encode_to_bytes<T, const N: usize>(val: &T) -> Bytes
where
    T: Serialize<rkyv::ser::serializers::AllocSerializer<N>>,
{
    let ret = rkyv::to_bytes::<_, N>(val).unwrap();
    // let mut r = BytesMut::new();
    // r.extend_from_slice(&ret);
    // r.freeze()
    ret.into_boxed_slice().into()
}

pub fn extract_bytes_from_archived_vec(raw_data: &Bytes, archived_data: &ArchivedVec<u8>) -> Bytes {
    let ptr_range = archived_data.as_ptr_range();
    let offset = ptr_range.start as usize - raw_data.as_ptr() as usize;
    let len = ptr_range.end as usize - ptr_range.start as usize;
    return raw_data.slice(offset..offset + len);
}

pub fn extract_bytes_from_archived_string(
    raw_data: &Bytes,
    archived_data: &ArchivedString,
) -> Bytes {
    let offset = archived_data.as_ptr() as usize - raw_data.as_ptr() as usize;
    let len = archived_data.len();
    if offset + len > raw_data.len() {
        return Bytes::new();
    }

    return raw_data.slice(offset..offset + archived_data.len());
}

pub fn extract_bytes_mut_from_archived_vec(
    raw_data: &mut BytesMut,
    archived_data: &ArchivedVec<u8>,
) -> BytesMut {
    let ptr_range = archived_data.as_ptr_range();
    let offset = ptr_range.start as usize - raw_data.as_ptr() as usize;
    let len = ptr_range.end as usize - ptr_range.start as usize;
    raw_data.split_off(offset).split_to(len)
}

pub fn vec_to_string(vec: Vec<u8>) -> String {
    unsafe { String::from_utf8_unchecked(vec) }
}
