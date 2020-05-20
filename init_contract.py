import json
from web3 import Web3
from solcx import compile_files, link_code, compile_source# web3.py instance
from solcx import install_solc
install_solc('v0.4.21')

w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

contracts = compile_files(['userRecords.sol', 'stringUtils.sol'])# separate main file and link file

main_contract = contracts.pop("userRecords.sol:userRecords")

library_link = contracts.pop("stringUtils.sol:StringUtils")# print bin part in  console you will see 'stringUtils' in that we need to link library address in that bin code.


def deploy_contract(contract_interface):
    # Instantiate and deploy contract
    contract = w3.eth.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin']
    )

    # Get transaction hash from deployed contract
    tx_hash = contract.constructor().transact(transaction={'from': w3.eth.accounts[1]})

    # Get tx receipt to get contract address
    tx_receipt = w3.eth.getTransactionReceipt(tx_hash)

    return tx_receipt['contractAddress']  # compile all contract files

# to that we have to deploy library code first then link it
library_address = {
    "stringUtils.sol:StringUtils": deploy_contract(library_link)
}

main_contract['bin'] = link_code(main_contract['bin'], library_address)# add abi(application binary interface) and transaction reciept in json file

with open('data.json', 'w') as outfile:
    data = {
        "abi": main_contract['abi'],
        "contract_address": deploy_contract(main_contract)
    }
    json.dump(data, outfile, indent=4, sort_keys=True)