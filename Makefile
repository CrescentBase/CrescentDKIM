.PHONY: test

all: snark-jwt-verify node_modules

test: snark-jwt-verify node_modules
	yarn exec mocha

node_modules/:
	yarn

clean:
	rm -rf snark-jwt-verify
	rm -rf node_modules

init:
	git clone --recurse-submodules https://github.com/TheFrozenFire/snark-jwt-verify
	npm install -g mocha
	npm install
	pip3 install dnspython
	pip3 install aiodns
	pip3 install PyNaCl

asdf:
	cd ./build_circuits/dkim_js && node ./generate_witness.js dkim.wasm ../input.json ../witness.wtns


