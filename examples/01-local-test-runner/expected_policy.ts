import * as iam from 'aws-cdk-lib/aws-iam';

export const generatedStatements = [
  new iam.PolicyStatement({
    sid: 'Dynamodb',
    effect: iam.Effect.ALLOW,
    actions: [
      'dynamodb:Query',
    ],
    resources: [
      '*',
    ],
  }),
  new iam.PolicyStatement({
    sid: 'Kms',
    effect: iam.Effect.ALLOW,
    actions: [
      'kms:Decrypt',
    ],
    resources: [
      '*',
    ],
  }),
  new iam.PolicyStatement({
    sid: 'S3',
    effect: iam.Effect.ALLOW,
    actions: [
      's3:GetObject',
      's3:ListBucket',
    ],
    resources: [
      '*',
    ],
  }),
];
