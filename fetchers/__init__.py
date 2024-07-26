import json
import os

from bitcoinrpc.authproxy import JSONRPCException, AuthServiceProxy

from utils import decimal_decoder, DecimalEncoder


def batch_getrawtransaction(rpc_connection, txids):
    cache_file = "input_transactions.json"
    cached_txs = {}
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            cached_txs = json.load(f, object_hook=decimal_decoder)

    txids_to_fetch = [txid for txid in txids if txid not in cached_txs]

    if txids_to_fetch:
        commands = [["getrawtransaction", txid, True] for txid in txids_to_fetch]
        try:
            new_txs = rpc_connection.batch_(commands)
            for tx in new_txs:
                if tx is not None:
                    cached_txs[tx['txid']] = tx

            with open(cache_file, 'w') as f:
                json.dump(cached_txs, f, cls=DecimalEncoder)
        except JSONRPCException as e:
            print(f"Error in batch getrawtransaction: {e}")

    return [cached_txs.get(txid) for txid in txids]


def get_block_transactions(rpc_connection, block_hash):
    cache_file = f"block_{block_hash}.json"
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            return json.load(f, object_hook=decimal_decoder)

    try:
        block = rpc_connection.getblock(block_hash, 2)
        with open(cache_file, 'w') as f:
            json.dump(block['tx'], f, cls=DecimalEncoder)
        return block['tx']
    except JSONRPCException as e:
        print(f"Error fetching block: {e}")
        return []


def connect_to_node():
    rpc_user = os.getenv('RPC_USER')
    rpc_password = os.getenv('RPC_PASSWORD')
    rpc_host = os.getenv('RPC_HOST', '127.0.0.1')
    rpc_port = os.getenv('RPC_PORT', '8332')

    rpc_connection = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}")
    return rpc_connection
