#!/bin/bash
# Downloads the latest cask list and fetches the scanner reports

scancount=0
scancountmax=25 # the maximum number of scans per run

# the wrap arg is "break" on macOS and "wrap" on Linux
echo wraptest | base64 --break=0 >/dev/null 2>&1 && WRAP=break || WRAP=wrap

DIR=urls
curl -O -fsSL http://formulae.brew.sh/api/cask.json

mkdir -p ${DIR}/

# walk through each element, get the checksum, and check it against VT
for urlraw in `jq -r '.[].url' cask.json | sort --sort=random`; do
    # the virustotal api expects a base64 of the url with padding equals stripped
    url64=`echo "${urlraw}" | base64 --${WRAP}=0 | tr -d '='`
    # the output file name is the sha256 of the URL itself
    urlpath=`echo "${urlraw}" | shasum -a 256 | cut -f 1 -d ' '`
    if [ ! -s "${DIR}/${urlpath}.json" ]; then
        echo "Scanning ${urlraw} -> ${DIR}/${urlpath}.json" 
        curl -o ${DIR}/"${urlpath}.json" -sSL --request GET --url "https://www.virustotal.com/api/v3/urls/${url64}" --header "x-apikey: ${VTAPIKEY}"

        cat ${DIR}/"${urlpath}.json" | jq '.data.attributes.names'
        #cat ${DIR}/"${urlpath}.json" | jq '.data.attributes.total_votes'

        # backoff if we hit a QuotaExceededError error code
        cat ${DIR}/"${urlpath}.json" | jq -e '.error.code == "QuotaExceededError"' && rm ${DIR}/"${urlpath}.json" && echo "QuotaExceededError: exiting" && exit 6

        # any URLs that are not found get a scan request
        cat ${DIR}/"${urlpath}.json" | jq -e '.error.code == "NotFoundError"' && echo "Requesting scan for ${urlraw}…" && curl -o ${DIR}/"${urlpath}.json" -sSL --request POST --url "https://www.virustotal.com/api/v3/urls" --header "x-apikey: ${VTAPIKEY}" --form url="${urlraw}"

        scancount=$((scancount + 1))
        if [ ${scancount} -gt ${scancountmax} ]; then
            break;
        fi
        sleep ${VTDELAY:-15} # public api request quota: 4/min, 500/day
    fi
done

# show a report of urls and errors
cat ${DIR}/*.json | jq '.error.code' | sort | uniq -c | sort -n

# clear out quota exceeded errors
# rm -fv EMPTY_ARG `jq -r 'select(.error.code == "QuotaExceededError") | input_filename' ${DIR}/*.json`
rm -fv EMPTY_ARG `jq -r 'select(.error.code != null) | input_filename' ${DIR}/*.json`

# clear out urls that were queued for analysis
rm -fv EMPTY_ARG `jq -r 'select(.data.type == "analysis") | input_filename' ${DIR}/*.json`

