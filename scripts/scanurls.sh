#!/bin/bash
# Downloads the latest cask list and fetches the scanner reports

DIR=urls
curl -O -fsSL http://formulae.brew.sh/api/cask.json

mkdir -p ${DIR}/

# clear out quota exceeded errors
# rm -fv EMPTY_ARG `jq -r 'select(.error.code == "QuotaExceededError") | input_filename' ${DIR}/*.json`
rm -fv EMPTY_ARG `jq -r 'select(.error.code != null) | input_filename' ${DIR}/*.json`

# clear out urls that were queued for analysis
rm -fv EMPTY_ARG `jq -r 'select(.data.type == "analysis") | input_filename' ${DIR}/*.json`

# walk through each element, get the checksum, and check it against VT
for urlraw in `jq -r '.[].url' cask.json | sort --sort=random`; do
    url64=`echo "${urlraw}" | base64 | tr -d '='`
    echo "${urlraw}" 
    if [ ! -s "${DIR}/${url64}.json" ]; then
        sleep 15 # public api request quota: 4/min, 500/day
        curl -o ${DIR}/"${url64}.json" -sSL --request GET --url "https://www.virustotal.com/api/v3/urls/${url64}" --header "x-apikey: ${VTAPIKEY}"

        cat ${DIR}/"${url64}.json" | jq '.data.attributes.names'
        #cat ${DIR}/"${url64}.json" | jq '.data.attributes.total_votes'

        # backoff if we hit a QuotaExceededError error code
        cat ${DIR}/"${url64}.json" | jq -e '.error.code == "QuotaExceededError"' && rm ${DIR}/"${url64}.json" && echo "QuotaExceededError: backing off…" && sleep 100

        # any URLs that are not found get a scan request
        cat ${DIR}/"${url64}.json" | jq -e '.error.code == "NotFoundError"' && echo "Requesting scan for ${urlraw}…" && curl -o ${DIR}/"${url64}.json" -sSL --request POST --url "https://www.virustotal.com/api/v3/urls" --header "x-apikey: ${VTAPIKEY}" --form url="${urlraw}"
    fi
done

# show a report of urls and errors
cat ${DIR}/*.json | jq '.error.code' | sort | uniq -c | sort -n

