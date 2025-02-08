#[derive(Drop, Clone, PartialEq, Serde)]
pub struct U64Words {
    pub words: Array<u64>,
    pub current_word: u64,
    pub byte_offset: u8
}


pub fn pow_256(pow: u8) -> u64 {
    if(pow == 0) {
        return 1_u64;
    } else if (pow == 1) {
        return 256_u64;
    } else if (pow == 2) {
        return 65536_u64;
    } else if (pow == 3) {
        return 16777216_u64;
    } else if (pow == 4) {
        return 4294967296_u64;
    } else if (pow == 5) {
        return 1099511627776_u64;
    } else if (pow == 6) {
        return 281474976710656_u64;
    } else {
        return 72057594037927936_u64;
    }
}

#[generate_trait]
pub impl U64WordsImpl of U64WordsTrait {
    fn new() -> U64Words {
        U64Words {
            words: array![],
            current_word: 0_u64,
            byte_offset: 0_u8, 
        }
    }

    fn append_word(ref self: U64Words, value: u64, byte_size: u8) {
        let mut val = value;
        let mut size = byte_size;
        let mut offset = self.byte_offset;

        while size > 0 {
            let available_bytes = 8 - offset;
            let bytes_to_store = if size < available_bytes { size } else { available_bytes };

            let shift_multiplier = pow_256(offset);
            let mask = pow_256(bytes_to_store) - 1;
            let part = val & mask;

            self.current_word = self.current_word + (part * shift_multiplier);

            val = val / pow_256(bytes_to_store);
            size = size - bytes_to_store;
            offset = offset + bytes_to_store;

            if offset == 8 {
                self.words.append(self.current_word);
                self.current_word = 0_u64;
                offset = 0;
            }
        };
        self.byte_offset = offset;
    }

    fn append_word_le(ref self: U64Words, value: u64, byte_size: u8) {
        let mut val = value;
        let mut size = byte_size;
        let mut offset = self.byte_offset;

        while size > 0 {
            let available_bytes = 8 - offset;
            let bytes_to_store = if size < available_bytes { size } else { available_bytes };

            let shift_multiplier = pow_256(offset);
            let mask = pow_256(bytes_to_store) - 1;
            let part = val & mask;

            self.current_word = self.current_word + (part * shift_multiplier);

            val = val / pow_256(bytes_to_store);
            size = size - bytes_to_store;
            offset = offset + bytes_to_store;

            if offset == 8 {
                self.words.append(self.current_word);
                self.current_word = 0_u64;
                offset = 0;
            }
        };
        self.byte_offset = offset;
    }

    fn finalize(ref self: U64Words) {
        if self.byte_offset > 0 {
            self.words.append(self.current_word);
            self.current_word = 0_u64;
            self.byte_offset = 0;
        }

    }

    fn get_words(self: U64Words) -> Span<u64> {
        self.words.span()
    }
}

#[cfg(test)]
mod tests { 
    use crate::u64word::{U64Words, U64WordsTrait, U64WordsImpl};

    #[test]
    fn test_u64_words() {
        let mut words :U64Words = U64WordsTrait::new();

        words.append_word(0x12AB, 2);   // 2 bytes (fills first 2 bytes)
        words.append_word(0x34CD56EF, 4); // 4 bytes (fills next 4 bytes)
        words.append_word(0x78, 1);     // 1 byte (fills next 1 byte)
        words.append_word(0xFF, 1);     // 1 byte (fills last byte of first u64)
        
        words.append_word(0x1122334455667788, 8); // Fully fills second u64
    
        words.finalize();  // Store last packed word if needed
    
        let packed_words = words.get_words();

        assert_eq!(*packed_words.at(0), 0x12AB34CD56EF78FF_u64);

    }
}