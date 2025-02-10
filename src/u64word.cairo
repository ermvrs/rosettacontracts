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