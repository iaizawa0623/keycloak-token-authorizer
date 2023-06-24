build:
	sam build -u

buildf:
	sam build -u --no-cached

local: build
	sam local invoke MyFunction

localf: buildf
	sam local invoke MyFunction

deploy: build
	sam deploy

deployf: buildf
	sam deploy

clean:
	yes | sam delete
