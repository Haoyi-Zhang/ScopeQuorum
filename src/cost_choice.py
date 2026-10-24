"""Replay retained TCP byte accounting and derive an explicit two-plane choice rule."""
from fractions import Fraction
import json
from pathlib import Path

SOURCE=Path(__file__).resolve().parents[1]/'results/tcp-read-20261014'
def require(value,message):
    if not value:raise ValueError(message)

def weighted_saving(client_saving,witness_extra,client_price):
    require(type(client_saving) is int and client_saving>0,'positive client saving')
    require(type(witness_extra) is int,'witness difference')
    price=Fraction(client_price)
    require(price>=0,'nonnegative byte price')
    return price*client_saving-witness_extra

def analyze(source=SOURCE):
    summary=json.loads((source/'summary.json').read_text())
    rows=summary['comparisons'];require(len(rows)==12,'trace denominator')
    seen=set();result=[]
    for row in rows:
        key=(row['family'],row['span'],row['churn'])
        require(key not in seen,'duplicate trace');seen.add(key)
        pair=[]
        for mode in ('prefix','scope'):
            trace=json.loads((source/('-'.join(map(str,key))+'-'+mode+'.json')).read_text())
            require(tuple(trace[x] for x in ('family','span','churn'))==key and trace['mode']==mode,'trace identity')
            require(len(trace['rows'])==row['read_pairs']==10,'read denominator')
            counters=trace['witness_counters']
            require(counters['wire_bytes']==sum(counters[x] for x in ('prefix_wire_bytes','sync_wire_bytes','reset_wire_bytes','certify_wire_bytes')),'witness byte accounting')
            require(trace['total_wire_bytes']==trace['client_wire_bytes']+counters['wire_bytes'],'plane accounting')
            for field,value in [('client',trace['client_wire_bytes']),('witness',counters['wire_bytes']),('total',trace['total_wire_bytes'])]:
                require(row[mode+'_'+field+'_bytes']==value,'summary/raw byte mismatch')
            require(trace['rows'][-1]['client_wire_bytes']==trace['client_wire_bytes'] and
                    trace['rows'][-1]['witness_counters']==counters,'terminal counters')
            pair.append(trace)
        for left,right in zip(pair[0]['rows'],pair[1]['rows']):
            require((left['root'],left['now'],left['expected_serve'])==(right['root'],right['now'],right['expected_serve']),'paired query mismatch')
            require(left['verdict']==right['verdict'] and left['verdict']['serve']==left['expected_serve'],'paired verdict mismatch')
        saving=row['prefix_client_bytes']-row['scope_client_bytes']
        extra=row['scope_witness_bytes']-row['prefix_witness_bytes']
        require(saving>0,'client saving premise')
        threshold=Fraction(extra,saving)
        result.append({'family':key[0],'span':key[1],'churn':key[2],
                       'client_saved_bytes':saving,'witness_extra_bytes':extra,
                       'break_even_client_price':str(threshold),
                       'equal_price_scope_cheaper':weighted_saving(saving,extra,1)>0})
    saving=sum(x['client_saved_bytes'] for x in result);extra=sum(x['witness_extra_bytes'] for x in result)
    return {'traces':12,'paired_reads':120,'scope_cheaper_at_equal_prices':sum(x['equal_price_scope_cheaper'] for x in result),
            'scope_cheaper_by_client_price':{str(price):sum(weighted_saving(x['client_saved_bytes'],x['witness_extra_bytes'],price)>0 for x in result) for price in (1,2,4)},
            'aggregate_client_saved_bytes':saving,'aggregate_witness_extra_bytes':extra,
            'aggregate_break_even_client_price':str(Fraction(extra,saving)),
            'rows':result,'scope':'Retained memory-backed TCP bytes only; no durability, CPU, storage or deployment-price measurement'}

if __name__=='__main__':print(json.dumps(analyze(),indent=2,sort_keys=True))
