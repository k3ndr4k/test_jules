const fs = require('fs');
const path = require('path');

async function benchmark() {
    const filePath = path.join(__dirname, 'test.md');
    fs.writeFileSync(filePath, 'hello world');

    const iters = 10000;

    // Test 1: access + readFile
    let startSync = performance.now();
    for (let i = 0; i < iters; i++) {
        try {
            await fs.promises.access(filePath);
            await fs.promises.readFile(filePath, 'utf8');
        } catch (e) {
            if (e.code !== 'ENOENT') throw e;
        }
    }
    let endSync = performance.now();

    // Test 2: just readFile
    let startAsync = performance.now();
    for (let i = 0; i < iters; i++) {
        try {
            await fs.promises.readFile(filePath, 'utf8');
        } catch (e) {
            // handle error
        }
    }
    let endAsync = performance.now();

    console.log(`Throughput (ms) - access + readFile: ${(endSync - startSync).toFixed(2)}`);
    console.log(`Throughput (ms) - readFile only: ${(endAsync - startAsync).toFixed(2)}`);

    // Let's also check Event Loop block time by having a setInterval
    function measureBlockTime(testFn) {
        return new Promise(resolve => {
            let lastTick = performance.now();
            let maxBlock = 0;
            const timer = setInterval(() => {
                const now = performance.now();
                const block = now - lastTick - 10;
                if (block > maxBlock) maxBlock = block;
                lastTick = now;
            }, 10);

            testFn().then((res) => {
                clearInterval(timer);
                resolve({ time: res, maxBlock });
            });
        });
    }

    const testSync = async () => {
        const start = performance.now();
        for (let i = 0; i < iters; i++) {
            try {
                await fs.promises.access(filePath);
                await fs.promises.readFile(filePath, 'utf8');
            } catch (e) {
                if (e.code !== 'ENOENT') throw e;
            }
        }
        return performance.now() - start;
    };

    const testAsync = async () => {
        const start = performance.now();
        for (let i = 0; i < iters; i++) {
            try {
                await fs.promises.readFile(filePath, 'utf8');
            } catch (e) { }
        }
        return performance.now() - start;
    };

    const resSync = await measureBlockTime(testSync);
    const resAsync = await measureBlockTime(testAsync);

    console.log(`Sync Block - max event loop delay: ${resSync.maxBlock.toFixed(2)}ms`);
    console.log(`Async Block - max event loop delay: ${resAsync.maxBlock.toFixed(2)}ms`);

    fs.unlinkSync(filePath);
}

benchmark();
