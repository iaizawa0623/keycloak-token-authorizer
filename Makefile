build:
	sam build -u

buildf:
	sam build -u --no-cached

local: build
	sam local invoke Hello

localf: buildf
	sam local invoke Hello

deploy: build
	sam deploy

deployf: buildf
	sam deploy

clean:
	yes | sam delete
