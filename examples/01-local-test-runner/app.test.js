/**
 * app.test.js - Node.js test suite demonstrating iam-shrink integration.
 *
 * Runs with standard Node: `node app.test.js` or `iam-shrink run -- node app.test.js`
 * Official @aws-sdk packages natively emit CSM datagrams when AWS_CSM_ENABLED=true.
 */

const dgram = require('dgram');

function emitCSM(service, api, statusCode = 200) {
  return new Promise((resolve) => {
    const portStr = process.env.AWS_CSM_PORT;
    if (!portStr) {
      return resolve();
    }

    const port = parseInt(portStr, 10);
    const host = process.env.AWS_CSM_HOST || '127.0.0.1';

    const client = dgram.createSocket('udp4');
    const message = Buffer.from(JSON.stringify({
      Version: 1,
      Type: 'ApiCall',
      Service: service,
      Api: api,
      Timestamp: Date.now(),
      Region: 'us-east-1',
      HttpStatusCode: statusCode,
      FinalHttpStatusCode: statusCode,
    }));

    client.send(message, 0, message.length, port, host, (err) => {
      client.close();
      resolve();
    });
  });
}

async function runTests() {
  console.log('Running Order Service Node.js integration tests...');

  // 1. DynamoDB Query
  await emitCSM('DynamoDB', 'Query');

  // 2. KMS Decrypt
  await emitCSM('KMS', 'Decrypt');

  // 3. S3 GetObject & ListBucket
  await emitCSM('S3', 'GetObject');
  await emitCSM('S3', 'ListBucket');

  // Allow loopback socket flush
  await new Promise(r => setTimeout(r, 60));
  console.log('✔ All 4 AWS operations completed successfully.');
}

runTests().catch(err => {
  console.error(err);
  process.exit(1);
});
