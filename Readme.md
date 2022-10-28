# About

# Development

```shell script
# create python venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt
# pip install .

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
python3 main.py

# run tests
python -m unittest
```

