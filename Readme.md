# About

# Development

```shell script
# create python venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -e .

# run test keycloak instance
# use local container or run it in cloud
docker run -it -p 8080:80 -p 8443:443 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin quay.io/keycloak/keycloak:15.0.2

# setup access to test keycloack
export KC_ENDPOINT=https://172.17.0.2:8443
export KEYCLOAK_API_CA_BUNDLE=
export KC_USER=admin
export KC_PASSWORD=admin
export KC_REALM=myrealm

# run code
alias kcload='./main.py --url=https://172.17.0.2:8443 --username=admin --password=admin'
kcload --datadir test/data/kcfetcher-latest --realm-name ci0-realm

# run tests
python -m unittest
```

