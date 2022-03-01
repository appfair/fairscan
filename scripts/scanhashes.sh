#!/bin/bash
# Downloads the latest cask list and fetches the scanner reports

scancount=0
scancountmax=25 # the maximum number of scans per run

DIR=files/

curl -O -fsSL http://formulae.brew.sh/api/cask.json

mkdir -p ${DIR}/

# walk through each element, get the checksum, and check it against VT
for hash in `jq -r '.[].sha256' cask.json | grep -v 'no_check' | sort --sort=random`; do
    #echo "${hash}"
    if [ ! -s "${DIR}/${hash}.json" ]; then
        curl -o ${DIR}/"${hash}.json" -sSL --request GET --url "https://www.virustotal.com/api/v3/files/${shasum}" --header "x-apikey: ${VTAPIKEY}"

        cat ${DIR}/"${hash}.json" | jq '.data.attributes.names'
        #cat ${DIR}/"${hash}.json" | jq '.data.attributes.total_votes'

        # backoff if we hit a QuotaExceededError error code
        cat ${DIR}/"${hash}.json" | jq -e '.error.code == "QuotaExceededError"' && rm ${DIR}/"${hash}.json" && sleep 100

        scancount=$((scancount + 1))
        if [ ${scancount} -gt ${scancountmax} ]; then
            break;
        fi
        sleep 15 # public api request quota: 4/min, 500/day
    fi
done

# show a report of files and errors
cat ${DIR}/*.json | jq '.error.code' | sort | uniq -c | sort -n

# clear out quota exceeded errors
# rm -fv EMPTY_ARG `jq -r 'select(.error.code == "QuotaExceededError") | input_filename' ${DIR}/*.json`
rm -fv EMPTY_ARG `jq -r 'select(.error.code != null) | input_filename' ${DIR}/*.json`

