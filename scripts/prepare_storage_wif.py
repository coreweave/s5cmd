#!/usr/bin/env python3
"""Prepare a private WIF policy proposal; never apply trust or permissions."""

import argparse
import json
import os
from pathlib import Path

S3_ACTIONS = ['s3:CreateBucket', 's3:DeleteBucket', 's3:GetBucketLocation',
              's3:ListBucket', 's3:GetObject', 's3:PutObject', 's3:DeleteObject',
              's3:ListBucketVersions', 's3:DeleteObjectVersion',
              's3:ListBucketMultipartUploads', 's3:ListMultipartUploadParts', 's3:AbortMultipartUpload']


def policy(subject):
    if not subject or any(character in subject for character in '*?[]\\\r\n'):
        raise ValueError('an exact observed subject is required')
    principal = 'role/https://token.actions.githubusercontent.com:' + subject
    return {'name': 's5cmd-storage-acceptance', 'version': 'v1alpha1', 'statements': [
        {'name': 'temporary-credential-exchange', 'effect': 'Allow',
         'actions': ['cwobject:CreateAccessKeyOIDC'], 'resources': ['*'], 'principals': [principal]},
        {'name': 'disposable-storage', 'effect': 'Allow', 'actions': S3_ACTIONS,
         'resources': ['s5cmd-acceptance-*', 's5cmd-acceptance-*/*'], 'principals': [principal]}]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subject', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    proposal = policy(args.subject)
    if not args.output.is_absolute() or args.output.parent.stat().st_mode & 0o077:
        parser.error('output must be in an absolute private directory')
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(proposal, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
