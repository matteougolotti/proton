use crypto::digest::Digest;
use crypto::sha2::Sha256;


// Returns the first 4 bytes (little endian) of sha256(sha256(data))
pub fn checksum(data: &[u8]) -> u32 {
    let mut hasher = Sha256::new();
    let mut checksum1: [u8; 32] = [0; 32];
    hasher.input(data);
    hasher.result(&mut checksum1);

    let mut hasher = Sha256::new();
    let mut checksum2: [u8; 32] = [0; 32];
    hasher.input(&checksum1);
    hasher.result(&mut checksum2);

    let checksum: [u8; 4] = [
        checksum2[0],
        checksum2[1],
        checksum2[2],
        checksum2[3]
    ];

    u32::from_le_bytes(checksum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        let data = "TEST";
        let expected: u32 = 3207904727;

        let result = checksum(&data.as_bytes());

        assert_eq!(expected, result);
    }
}
