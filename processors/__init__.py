from decimal import Decimal

from fetchers import batch_getrawtransaction
from script import derive_address
from utils import btc_to_satoshis

def get_input_transactions(rpc_connection, transactions):
    input_txids = [vin['txid'] for tx in transactions for vin in tx['vin'] if 'txid' in vin]
    input_txs = batch_getrawtransaction(rpc_connection, input_txids)
    return {tx['txid']: tx for tx in input_txs if tx is not None}


def process_coinbase_transaction(tx, vin_index, unique_txs, ws1, address_stats, target_address, target_address_txs):
    for vout_index, vout in enumerate(tx['vout']):
        amount_satoshis = btc_to_satoshis(vout['value'])
        output_address = derive_address(vout['scriptPubKey'], vout['scriptPubKey'].get('asm', ''))

        unique_key = ('Coinbase', vin_index, tx['txid'], vout_index)
        if unique_key not in unique_txs:
            unique_txs.add(unique_key)
            ws1.append([
                'Coinbase',
                vin_index,
                tx['txid'],
                vout_index,
                'Coinbase (Newly generated coins)',
                output_address,
                amount_satoshis
            ])

            address_stats[output_address]['balance_in'] += Decimal(amount_satoshis)
            address_stats[output_address]['tx_count'] += 1

            if output_address == target_address:
                target_address_txs.append({
                    'type': 'output',
                    'txid': tx['txid'],
                    'vout_index': vout_index,
                    'amount': amount_satoshis,
                    'address': output_address
                })


def process_regular_transaction(tx, vin, vin_index, input_tx_dict, unique_txs, ws1, address_stats, target_address, target_address_txs):
    input_tx = input_tx_dict.get(vin['txid'])
    if input_tx:
        input_vout = input_tx['vout'][vin['vout']]
        input_address = derive_address(input_vout['scriptPubKey'],
                                       input_vout['scriptPubKey'].get('asm', ''))
        input_amount = btc_to_satoshis(input_vout['value'])

        process_transaction_input(vin, input_address, input_amount, unique_txs, address_stats, target_address, target_address_txs, tx['txid'], vin_index)
        process_transaction_outputs(tx, vin, input_address, unique_txs, ws1, address_stats, target_address, target_address_txs)
    else:
        print(f"Warning: Input transaction {vin['txid']} not found")


def process_transaction_input(vin, input_address, input_amount, unique_txs, address_stats, target_address, target_address_txs, tx_id, vin_index):
    unique_input_key = (vin['txid'], vin['vout'])
    if unique_input_key not in unique_txs:
        unique_txs.add(unique_input_key)
        address_stats[input_address]['balance_out'] += Decimal(input_amount)
        address_stats[input_address]['tx_count'] += 1

        if input_address == target_address:
            target_address_txs.append({
                'type': 'input',
                'txid': tx_id,
                'vin_index': vin_index,
                'amount': input_amount,
                'address': input_address
            })


def process_transaction_outputs(tx, vin, input_address, unique_txs, ws1, address_stats, target_address, target_address_txs):
    for vout_index, vout in enumerate(tx['vout']):
        amount_satoshis = btc_to_satoshis(vout['value'])
        output_address = derive_address(vout['scriptPubKey'], vout['scriptPubKey'].get('asm', ''))

        unique_key = (tx['txid'], vout_index)
        if unique_key not in unique_txs:
            unique_txs.add(unique_key)
            ws1.append([
                vin['txid'],
                vin['vout'],
                tx['txid'],
                vout_index,
                input_address,
                output_address,
                amount_satoshis
            ])

            address_stats[output_address]['balance_in'] += Decimal(amount_satoshis)
            address_stats[output_address]['tx_count'] += 1

            if output_address == target_address:
                target_address_txs.append({
                    'type': 'output',
                    'txid': tx['txid'],
                    'vout_index': vout_index,
                    'amount': amount_satoshis,
                    'address': output_address
                })
