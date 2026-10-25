from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from app.aws import collect, validate_policy


def fake_session(account="111122223333", root=False, deny_inventory=False):
    clients = {}
    for name in ['sts', 'iam', 'lambda', 's3', 'cloudtrail', 'accessanalyzer', 'organizations', 'securityhub', 'config']:
        client = MagicMock()
        client.meta = SimpleNamespace(service_model=SimpleNamespace(service_name=name))
        client.can_paginate.return_value = True
        client.get_paginator.return_value.paginate.return_value = []
        clients[name] = client
    clients['sts'].get_caller_identity.return_value = {'Account': account, 'Arn': f'arn:aws:iam::{account}:' + ('root' if root else 'user/scanner')}
    clients['organizations'].describe_organization.return_value = {}
    if deny_inventory:
        clients['iam'].get_paginator.return_value.paginate.side_effect = ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'no'}}, 'GetAccountAuthorizationDetails')
    session = MagicMock()
    session.client.side_effect = lambda name, **kw: clients[name]
    return session, clients


def test_root_rejected():
    session, _ = fake_session(root=True)
    with patch('app.aws.boto3.Session', return_value=session), pytest.raises(ValueError, match='Root'):
        collect(expected_account_id='111122223333')


def test_wrong_account_rejected_before_inventory():
    session, clients = fake_session()
    with patch('app.aws.boto3.Session', return_value=session), pytest.raises(ValueError, match='authorized'):
        collect(expected_account_id='999999999999')
    clients['iam'].get_paginator.assert_not_called()


def test_partial_scan_is_not_secure():
    session, _ = fake_session(deny_inventory=True)
    with patch('app.aws.boto3.Session', return_value=session):
        data = collect(expected_account_id='111122223333')
    assert not data['synthetic'] and not data['controls_complete']
    assert any(e['operation'] == 'get_account_authorization_details' for e in data['errors'])
    assert any(e['code'] == 'NotEvaluated' for e in data['errors'])


def test_managed_policy_group_and_boundary_resolution():
    session, clients = fake_session()
    policy = {'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]}
    clients['iam'].get_paginator.return_value.paginate.return_value = [{
        'UserDetailList': [{'Arn':'arn:aws:iam::111122223333:user/alice','UserName':'alice','GroupList':['readers'],
                            'PermissionsBoundary': {'PermissionsBoundaryArn':'arn:boundary'}}],
        'GroupDetailList':[{'GroupName':'readers','GroupPolicyList':[{'PolicyDocument':policy}]}],
        'Policies':[{'Arn':'arn:boundary','PolicyVersionList':[{'IsDefaultVersion':True,'Document':policy}]}]
    }]
    with patch('app.aws.boto3.Session', return_value=session):
        data = collect()
    assert data['identities'][0]['policies'] == [policy]
    assert data['identities'][0]['boundary'] == policy


def test_policy_validation_pagination():
    client = MagicMock()
    client.validate_policy.side_effect = [{'findings':[{'issueCode':'ONE'}], 'nextToken':'next'}, {'findings':[{'issueCode':'TWO'}]}]
    with patch('app.aws.boto3.Session') as session:
        session.return_value.client.return_value = client
        assert len(validate_policy({'Statement':[]})) == 2
    assert client.validate_policy.call_args.kwargs['nextToken'] == 'next'
