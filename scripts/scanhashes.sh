#!/bin/bash
# Downloads the latest cask list and fetches the scanner reports

MAXSIZE=1g
DIR=files/
SCANLIMIT=10 # the maximum number of scans per run
scancount=0 # the current scan index

# grab the latest cask list
curl -O -fsSL http://formulae.brew.sh/api/cask.json

mkdir -p ${DIR}/
mkdir -p /tmp/fairscan/

# walk through each element, get the checksum, and check it against VT
for shaurl in `jq -r '.[] | "\(.sha256)|\(.url)"' cask.json | sort --sort=random`; do

    hash=`echo "${shaurl}" | cut -f 1 -d '|'`
    url=`echo "${shaurl}" | cut -f 2- -d '|'`

    if [ ! -s "${DIR}/${hash}.json" ]; then
        orig_hash="${hash}"

        # there is no efficient way to track no_check files
        if [ "${hash}" == "no_check" ]; then continue; fi

        echo "HASH: ${hash}"
        echo "URL: ${url}"

        base=`basename "${url}"`
        dlpath="/tmp/fairscan/${base}"

        # when no hash specified, the only option is to download and check the file
        if [ "${hash}" == "no_check" ]; then
            curl -fL --max-filesize "${MAXSIZE}" -o "${dlpath}" "${url}" || continue;
            hash=`shasum -a 256 "${dlpath}" | cut -f 1 -d ' '`
            echo "HASH2: ${hash}"
            if [ -s "${DIR}/${hash}.json" ]; then
                echo "Hash JSON exists for no_check -> ${hash}. Continuing…"
                continue;
            fi
        fi

        curl -o ${DIR}/"${hash}.json" -sSL --request GET --url "https://www.virustotal.com/api/v3/files/${hash}" --header "x-apikey: ${VTAPIKEY}"

        cat ${DIR}/"${hash}.json" | jq '.data.attributes.names'
        #cat ${DIR}/"${hash}.json" | jq '.data.attributes.total_votes'

        # backoff if we hit a QuotaExceededError error code
        cat ${DIR}/"${hash}.json" | jq -e '.error.code == "QuotaExceededError"' && rm ${DIR}/"${hash}.json" && echo "QuotaExceededError" && exit 6

        # any URLs that are not found get a scan request
        if (cat ${DIR}/"${hash}.json" | jq -e '.error.code == "NotFoundError"'); then
            uploadurl=`curl -fsSL "https://www.virustotal.com/api/v3/files/upload_url" --header "x-apikey: ${VTAPIKEY}" | jq -r '.data'`

            # download the file, but only if we haven't already grabbed it for the hash
            if [ "${orig_hash}" != "no_check" ]; then
                echo "Downloading ${url} to ${dlpath}…"
                curl -fsSL --max-filesize "${MAXSIZE}" -o "${dlpath}" "${url}"
            fi

            echo "Requesting scan for ${url}…"
            curl -o ${DIR}/"${hash}.json" -sSL --request POST --url "${uploadurl}" --header "x-apikey: ${VTAPIKEY}" --header 'Accept: application/json' --header 'Content-Type: multipart/form-data' --form "file=@${dlpath}"
        fi

        cat ${DIR}/"${hash}.json" | jq -e '.error.code == "QuotaExceededError"' && rm ${DIR}/"${hash}.json" && exit 6

        scancount=$((scancount + 1))
        if [ ${scancount} -gt ${SCANLIMIT} ]; then
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

# clear out files that were downloades as HTML
rm -vf EMPTY_ARG `grep -rl '^<html>' ${DIR}/`



