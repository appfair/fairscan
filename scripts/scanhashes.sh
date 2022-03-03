#!/bin/bash
# Downloads the latest cask list and fetches the scanner reports

scancount=0
scancountmax=25 # the maximum number of scans per run

DIR=files/

curl -O -fsSL http://formulae.brew.sh/api/cask.json

mkdir -p ${DIR}/

# walk through each element, get the checksum, and check it against VT
for shaurl in `jq -r '.[] | "\(.sha256)|\(.url)"' cask.json | sort --sort=random`; do

    hash=`echo "${shaurl}" | cut -f 1 -d '|'`
    url=`echo "${shaurl}" | cut -f 2- -d '|'`

    if [ ! -s "${DIR}/${hash}.json" ]; then
        echo "HASH: ${hash}"
        echo "URL: ${url}"
        #if [ "${hash}" == "no_check" ]; then continue; fi

        dlpath="/tmp/${hash}.download"

        curl -o ${DIR}/"${hash}.json" -sSL --request GET --url "https://www.virustotal.com/api/v3/files/${shasum}" --header "x-apikey: ${VTAPIKEY}"

        cat ${DIR}/"${hash}.json" | jq '.data.attributes.names'
        #cat ${DIR}/"${hash}.json" | jq '.data.attributes.total_votes'

        # backoff if we hit a QuotaExceededError error code
        cat ${DIR}/"${hash}.json" | jq -e '.error.code == "QuotaExceededError"' && rm ${DIR}/"${hash}.json" && exit 6

        # any URLs that are not found get a scan request
        cat ${DIR}/"${hash}.json" | jq -e '.error.code == "NotFoundError"' && echo "Downloading ${url}…" && ulurl=`curl -fsSL "https://www.virustotal.com/api/v3/files/upload_url" --header "x-apikey: ${VTAPIKEY}" | jq -r '.data'` && curl -fsSL --max-filesize 500m -o "${dlpath}" "${url}" && echo "Requesting scan for ${url}…" && curl -o ${DIR}/"${hash}.json" -sSL --request POST --url "${ulurl}" --header "x-apikey: ${VTAPIKEY}" --header 'Accept: application/json' --header 'Content-Type: multipart/form-data' --form "file=@${dlpath}"

        # for no_check hashes, rename the file to the actual hash of the file
        if [ "${hash}" == "no_check" ]; then filehash=`shasum -a 256 ${DIR}/"${hash}.json" | cut -f 1 -d ' '; mv ${DIR}/"${hash}.json" ${DIR}/"${newhash}.json"`; hash=${newhash}; fi

        cat ${DIR}/"${hash}.json" | jq -e '.error.code == "QuotaExceededError"' && rm ${DIR}/"${hash}.json" && exit 6

        scancount=$((scancount + 1))
        if [ ${scancount} -gt ${scancountmax} ]; then
            break;
        fi
        sleep ${VTDELAY:-15} # public api request quota: 4/min, 500/day
    fi
done

# show a report of files and errors
cat ${DIR}/*.json | jq '.error.code' | sort | uniq -c | sort -n

# clear out quota exceeded errors
# rm -fv EMPTY_ARG `jq -r 'select(.error.code == "QuotaExceededError") | input_filename' ${DIR}/*.json`
rm -fv EMPTY_ARG `jq -r 'select(.error.code != null) | input_filename' ${DIR}/*.json`

# clear out urls that were queued for analysis
rm -fv EMPTY_ARG `jq -r 'select(.data.type == "analysis") | input_filename' ${DIR}/*.json`

