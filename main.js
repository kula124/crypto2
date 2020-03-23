const bb = require('bluebird')
const axios = require('axios').default.create({
    baseURL: 'http://localhost:3000/',
    headers: { 'Content-Type': 'application/json' }
})

const { log, error } = console
const { decrypts } = require('./decrypt')

const AsciiTableInit = (s, e) => { // should be singleton but I'm careful ^ ^
    let current = s
    const end = e
    return current == end ? null : () => current != end ? String.fromCharCode(current++) : null
}

const queryApi = (payload) => axios.post('/ecb', {
    plaintext: payload
})
    .then(({ data }) => data.ciphertext)
    .then(ct => ct.substring(0, 16))


axios.get('/ecb/challenge')
    .then(r => r.data)
    .then(async theJoke => {
        // 0) get cypher
        // 1) generate plaintext who's bit-length is block size - 1 (ie 120)
        // 2) hit the server with 1) payload + ascii chars until match with 1) cypher is found
        // 3) repeat 2) with block-size 128 - 2, 3, 4,....16
        // 4) Once you have the cookie, solve the challenge
        //--------------
        // Preps:
        const startOfAsciiTable = 48
        const endOfAsciiTable = 90
        let asciiGenerator
        const resetAsciiGenerator = () => {
            asciiGenerator = AsciiTableInit(startOfAsciiTable, endOfAsciiTable)
        }
        const blockCharLength = Number.parseInt(256 / 16)
        // a char is UTF-16 encoded, ie 16 bytes
        let initialPlainText = ''
        // 1)------------------------------------------------
        for (let i = 0; i < blockCharLength; i++) {
            const v = i > 9 ? i - 10 : i
            initialPlainText = initialPlainText.concat(v.toString())
        }
        const allPlainTexts = []
        for (let i = 1; i < blockCharLength; i++) {
            allPlainTexts.push(initialPlainText.substring(0, initialPlainText.length - i))
        }
        let cookieSolution = ''
        //--------------------------------------------- 1)

        // 3) ---------------------------------------
        await bb.Promise.each(allPlainTexts, async pt => {
            // 2) ----------------------------
            let lastCypher = await queryApi(pt)
            let newCypher = ''
            resetAsciiGenerator()

            let currentChar = asciiGenerator()
            let p = pt.concat(cookieSolution).concat(currentChar)
            while (newCypher !== lastCypher && !!currentChar) {
                newCypher = await queryApi(p)
                currentChar = p.split('').pop()
                p = pt.concat(cookieSolution).concat(asciiGenerator())
            }
            if (!currentChar) {
                error('FAIL')
                process.exit()
            }
            // -----------------------------2)
            cookieSolution = cookieSolution.concat(currentChar)
            // --------------------------- 3)
        })

        // 4)---------------------------------------------------------
        log('COOKIE FOUND: ', cookieSolution)
        const solution = await decrypts({ cookie: cookieSolution, cypher: theJoke.ciphertext, ivs: theJoke.iv.toString() })
        log(solution)
    })
