import requests, concurrent.futures
s = requests.Session(); s.get("http://167.172.204.79:5105/")
with concurrent.futures.ThreadPoolExecutor(10) as ex:
    results = list(ex.map(lambda _: s.post("http://167.172.204.79:5105/level1/redeem").json(), range(10)))
    print(results)