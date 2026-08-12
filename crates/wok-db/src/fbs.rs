//! FlatBuffers codec for Meta, NegentropyFilter, and CompressionDictionary.
//!
//! Compatible with C++ rasgueadb tables generated from `defaultDb.schema.fbs`.
//! Decoder walks the vtable so C++-written records are readable even if
//! encoder padding differs.

use crate::DbError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub db_version: u64,
    pub endianness: u64,
    pub negentropy_modification_counter: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegentropyFilterRec {
    pub filter: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionDictionaryRec {
    pub dict: Vec<u8>,
}

fn root_table(buf: &[u8]) -> Result<usize, DbError> {
    if buf.len() < 8 {
        return Err(DbError::msg("flatbuffer too short"));
    }
    let off = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    if off + 4 > buf.len() {
        return Err(DbError::msg("flatbuffer root out of range"));
    }
    Ok(off)
}

fn vtable_field_offset(buf: &[u8], table_off: usize, field_id: usize) -> Result<u16, DbError> {
    let soffset = i32::from_le_bytes(buf[table_off..table_off + 4].try_into().unwrap());
    let vtable_off = (table_off as i32 - soffset) as usize;
    if vtable_off + 4 > buf.len() {
        return Err(DbError::msg("vtable out of range"));
    }
    let vtable_size =
        u16::from_le_bytes(buf[vtable_off..vtable_off + 2].try_into().unwrap()) as usize;
    let entry = 4 + field_id * 2;
    if entry + 2 > vtable_size {
        return Ok(0);
    }
    let pos = vtable_off + entry;
    if pos + 2 > buf.len() {
        return Err(DbError::msg("vtable field out of range"));
    }
    Ok(u16::from_le_bytes(buf[pos..pos + 2].try_into().unwrap()))
}

fn get_u64(buf: &[u8], table_off: usize, field_id: usize) -> Result<u64, DbError> {
    let off = vtable_field_offset(buf, table_off, field_id)?;
    if off == 0 {
        return Ok(0);
    }
    let pos = table_off + off as usize;
    if pos + 8 > buf.len() {
        return Err(DbError::msg("u64 field out of range"));
    }
    Ok(u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap()))
}

fn get_string(buf: &[u8], table_off: usize, field_id: usize) -> Result<String, DbError> {
    let bytes = get_bytes(buf, table_off, field_id)?;
    String::from_utf8(bytes).map_err(|_| DbError::msg("flatbuffer string not utf-8"))
}

fn get_bytes(buf: &[u8], table_off: usize, field_id: usize) -> Result<Vec<u8>, DbError> {
    let off = vtable_field_offset(buf, table_off, field_id)?;
    if off == 0 {
        return Ok(Vec::new());
    }
    let ptr_pos = table_off + off as usize;
    if ptr_pos + 4 > buf.len() {
        return Err(DbError::msg("string offset out of range"));
    }
    let rel = u32::from_le_bytes(buf[ptr_pos..ptr_pos + 4].try_into().unwrap()) as usize;
    let str_pos = ptr_pos + rel;
    if str_pos + 4 > buf.len() {
        return Err(DbError::msg("string length out of range"));
    }
    let len = u32::from_le_bytes(buf[str_pos..str_pos + 4].try_into().unwrap()) as usize;
    let data_pos = str_pos + 4;
    if data_pos + len > buf.len() {
        return Err(DbError::msg("string data out of range"));
    }
    Ok(buf[data_pos..data_pos + len].to_vec())
}

pub fn decode_meta(buf: &[u8]) -> Result<Meta, DbError> {
    let t = root_table(buf)?;
    Ok(Meta {
        db_version: get_u64(buf, t, 0)?,
        endianness: get_u64(buf, t, 1)?,
        negentropy_modification_counter: get_u64(buf, t, 2)?,
    })
}

pub fn decode_negentropy_filter(buf: &[u8]) -> Result<NegentropyFilterRec, DbError> {
    let t = root_table(buf)?;
    Ok(NegentropyFilterRec {
        filter: get_string(buf, t, 0)?,
    })
}

pub fn decode_compression_dictionary(buf: &[u8]) -> Result<CompressionDictionaryRec, DbError> {
    let t = root_table(buf)?;
    Ok(CompressionDictionaryRec {
        dict: get_bytes(buf, t, 0)?,
    })
}

pub fn encode_meta(meta: &Meta) -> Vec<u8> {
    let mut fbb = flatbuffers::FlatBufferBuilder::new();
    let start = fbb.start_table();
    fbb.push_slot::<u64>(8, meta.negentropy_modification_counter, 0);
    fbb.push_slot::<u64>(6, meta.endianness, 0);
    fbb.push_slot::<u64>(4, meta.db_version, 0);
    let loc = fbb.end_table(start);
    fbb.finish(loc, None);
    fbb.finished_data().to_vec()
}

pub fn encode_negentropy_filter(filter: &str) -> Vec<u8> {
    let mut fbb = flatbuffers::FlatBufferBuilder::new();
    let s = fbb.create_string(filter);
    let start = fbb.start_table();
    fbb.push_slot_always::<flatbuffers::WIPOffset<_>>(4, s);
    let loc = fbb.end_table(start);
    fbb.finish(loc, None);
    fbb.finished_data().to_vec()
}

pub fn encode_compression_dictionary(dict: &[u8]) -> Vec<u8> {
    let mut fbb = flatbuffers::FlatBufferBuilder::new();
    let v = fbb.create_vector(dict);
    let start = fbb.start_table();
    fbb.push_slot_always::<flatbuffers::WIPOffset<_>>(4, v);
    let loc = fbb.end_table(start);
    fbb.finish(loc, None);
    fbb.finished_data().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_roundtrip() {
        let m = Meta {
            db_version: 3,
            endianness: 1,
            negentropy_modification_counter: 1,
        };
        let buf = encode_meta(&m);
        assert_eq!(decode_meta(&buf).unwrap(), m);
    }

    #[test]
    fn filter_roundtrip() {
        let buf = encode_negentropy_filter("{}");
        assert_eq!(decode_negentropy_filter(&buf).unwrap().filter, "{}");
    }

    #[test]
    fn decode_cpp_meta_fixture() {
        // Captured from strfry-created empty DB (mdb_dump of rasgueadb_defaultDb__Meta).
        let hex = "140000000000000000000a001c0014000c0004000a000000010000000000000001000000000000000300000000000000";
        let buf = hex::decode(hex).unwrap();
        let m = decode_meta(&buf).unwrap();
        assert_eq!(m.db_version, 3);
        assert_eq!(m.endianness, 1);
        assert_eq!(m.negentropy_modification_counter, 1);
    }

    #[test]
    fn decode_cpp_filter_fixture() {
        let hex = "0c00000000000600080004000600000004000000020000007b7d0000";
        let buf = hex::decode(hex).unwrap();
        assert_eq!(decode_negentropy_filter(&buf).unwrap().filter, "{}");
    }
}
