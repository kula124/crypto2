
(async () => {
    const a = ['a', 'b', 'c', 'd']
    const bb = require('bluebird')

    const b = await bb.Promise.map(a, async e => {
        return new Promise((resolve, reject) => {
            setTimeout(() => console.log(e) || resolve('a'), 1000)
        })
    }, { concurrency: 1 })
    console.log(b)
})()
