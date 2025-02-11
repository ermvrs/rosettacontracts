## Unit Test Results

| Test Function Name | Step Count | Keccaks | Gas |
| :---------------- | :------: | ----: | ----: |
| encoding::test_deserialize_u256|   3100   | 0 | 17 |
| encoding::test_deserialize_u256_span_max |   11755   | 0 | 64 |
| encoding::test_deserialize_u256_span_low_max |   11515   | 0 | 61 |
| encoding::test_deserialize_u256_span |   11462   | 0 | 61 |
| encoding::rlp_encode_eip1559_transaction |   24851   | 0 | 106 |
| encoding::test_tx_bytes_decoding |   1427   | 0 | 8 |
| encoding::test_byte_array_from_felts_long_two |   17692   | 0 | 93 |
| encoding::test_deserialize_u256_span_high_max |   11739   | 0 | 64 |
| encoding::rlp_encode_transaction_value |   24612   | 0 | 107 |
| encoding::rlp_encode_legacy_transaction_empty_calldata |   19521   | 0 | 86 |
| encoding::test_deserialize_u256_span_multi_max |   23448   | 0 | 128 |
| encoding::test_byte_array_from_felts |   10972   | 0 | 58 |
| encoding::test_tx_bytes_decoding_initial_zeroes |   1427   | 0 | 8 |
| encoding::test_tx_bytes_decoding_zeroes |   1457   | 0 | 8 |
| encoding::rlp_encode_legacy_transaction_with_calldata |   20118   | 0 | 87 |
| encoding::test_byte_array_from_felts_long |   10372   | 0 | 57 |
| utils::test_eth_function_signature_approve |   15328   | 1 | 76 |
| encoding::test_deserialize_u256_span_multi_zero |   22951   | 0 | 123 |
| utils::test_eth_fn_signature_long |   32997   | 1 | 160 |
| utils::test_eth_fn_signature |   21786   | 1 | 108 |
| utils::test_eth_function_signature_transfer |   15646   | 1 | 77 |
| encoding::test_deserialize_u256_span_zero |   11462   | 0 | 61 |
| utils::test_generate_tx_hash |   40311   | 1 | 170 |
| utils::test_generate_legacy_tx_hash |   38416   | 1 | 170 |
| utils::test_eth_function_signature_transfer_from |   21272   | 1 | 101 |
| utils::test_merge_one |   199   | 0 | 1 |
| utils::test_eth_function_signature_total_supply |   9800   | 1 | 48 |
| utils::test_merge_two |   302   | 0 | 2 |
| utils::test_parse_function_name_long |   18113   | 0 | 94 |
| utils::test_merge_wrong_sanity |   95   | 0 | 1 |
| utils::test_parse_function_name |   10649   | 0 | 58 |
| utils::test_parse_eip1559_transaction_empty_calldata |   154   | 0 | 1 |
| utils::test_prepare_multicall_context |   667   | 0 | 2 |
| utils::test_parse_eip1559_transaction_usual |   55637   | 0 | 297 |
| utils::test_parse_legacy_transaction_empty_calldata |   146   | 0 | 1 |
| utils::test_sn_entrypoint |   14087   | 1 | 72 |
| utils::test_parse_legacy_transaction_usual |   55630   | 0 | 297 |
| utils::test_validate_target_function_correct |   36657   | 2 | 184 |
| utils::test_bytes_deserialize |   173   | 0 | 1 |
| utils::test_validate_target_function_wrong |   33742   | 1 | 164 |
## Integration Test Results
| Test Function Name | Step Count | Keccaks | Gas |
| :---------------- | :------: | ----: | ----: |
| account::test_execute_erc20_transfer_with_value|   58   | 0 | 1 |
| account::test_signature_validation_legacy_invalid |   168633   | 1 | 1782 |
| account::test_signature_validation_eip1559 |   168646   | 1 | 1782 |
| account::test_signature_validation_legacy |   168640   | 1 | 1782 |
| account::test_signature_wrong_address |   168639   | 1 | 1782 |
| account::check_initial_variables |   12601   | 0 | 1218 |
| account::test_execute_value_transfer_and_call |   60451   | 2 | 2082 |
| account::test_execute_erc20_transfer |   74950   | 2 | 2564 |
| account::test_execute_erc20_transfer_exceeds_balance |   28323   | 0 | 2349 |
| account::test_legacy_transaction_validation_value_transfer_only |   248964   | 3 | 2107 |
| account::test_execute_erc20_transfer_legacy |   74950   | 2 | 2564 |
| account::test_validation_with_access_list |   241   | 0 | 1 |
| account::test_transaction_validation_calldata_wrong_target_function |   150566   | 2 | 1788 |
| account::test_transaction_validation_unsupported_tx_type |   60222   | 1 | 1391 |
| account::test_wrong_signature |   168633   | 1 | 1782 |
| rosettanet::rosettanet_check_precalculated_address |   11996   | 0 | 1216 |
| rosettanet::rosettanet_deploy_initial_dev |   5966   | 0 | 847 |
| account::test_transaction_validation_calldata_and_value_transfer |   293753   | 5 | 2309 |
| account::test_transaction_validation_calldata |   442192   | 5 | 2950 |
| rosettanet::rosettanet_non_dev_set_class |   8685   | 0 | 848 |
| rosettanet::rosettanet_register_contract |   8685   | 0 | 982 |
| account::test_validation_real_data_failing |   440540   | 5 | 3403 |
| rosettanet::rosettanet_set_class |   8373   | 0 | 854 |
| rosettanet::rosettanet_register_existing_contract |   7775   | 0 | 980 |
| account::test_legacy_transaction_validation_calldata |   418867   | 5 | 2877 |
| account::test_execute_value_transfer_not_enough_balance |   17244   | 0 | 1582 |
| account::test_transaction_validation_value_transfer_only |   264189   | 3 | 2165 |
| account::test_multicall_with_value |   20411   | 0 | 1367 |
| account::test_multicall_validate_actual_values |   1269989   | 9 | 6558 |
| account::test_legacy_transaction_validation_calldata_invalid_signature |   417837   | 5 | 2877 |
| account::test_execute_value_transfer_wrong_value_on_sig |   23561   | 0 | 1727 |
| account::test_signature_validation |   168646   | 1 | 1782 |
| account::test_validate_multicall_transaction |   1052351   | 7 | 5634 |
| account::test_validate_multicall_transaction_wrong_signature |   1050640   | 7 | 5633 |
| account::test_unimplemented_feature |   20409   | 0 | 1367 |
| account::test_multicall_wrong_selector |   20409   | 0 | 1367 |
| account::test_execute_value_transfer |   32252   | 0 | 1814 |
| account::test_execute_multicall_transaction |   540497   | 4 | 3643 |
| account::test_multicall_validate_actual_values_swap |   2644975   | 19 | 12318 |

