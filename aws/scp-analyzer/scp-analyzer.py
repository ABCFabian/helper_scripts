import boto3
import json
from anytree import Node, RenderTree
import os
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SCPAnalyzer:
    def __init__(self, profile_name=None, output_dir='scp_output'):
        if profile_name:
            self.session = boto3.Session(profile_name=profile_name)
        else:
            self.session = boto3.Session(
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                aws_session_token=os.environ.get('AWS_SESSION_TOKEN'),
                region_name=os.environ.get('AWS_DEFAULT_REGION')
            )
        self.org_client = self.session.client('organizations')
        self.scp_tree = Node("Organization")
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.all_scps = self.collect_scps()

    def collect_scps(self):
        try:
            scps = self.org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']
            return {scp['Id']: scp for scp in scps}
        except Exception as e:
            logger.error(f"Error collecting SCPs: {str(e)}")
            return {}

    def map_scps_to_ous(self):
        try:
            roots = self.org_client.list_roots()['Roots']
            for root in roots:
                root_id = root['Id']
                root_name = root['Name']
                root_node = Node(f"Root: {root_name}", parent=self.scp_tree)
                
                # Attach SCPs to Root
                self._attach_and_save_scps(root_id, root_node, 'Root')
                
                # Process child OUs
                child_ous = self.org_client.list_organizational_units_for_parent(ParentId=root_id)['OrganizationalUnits']
                for child_ou in child_ous:
                    self._traverse_ou(child_ou['Id'], root_node)
        except Exception as e:
            logger.error(f"Error mapping SCPs to OUs: {str(e)}")

    def _traverse_ou(self, ou_id, parent_node):
        try:
            ou = self.org_client.describe_organizational_unit(OrganizationalUnitId=ou_id)['OrganizationalUnit']
            ou_node = Node(f"OU: {ou['Name']}", parent=parent_node)
            
            # Attach SCPs to OU
            self._attach_and_save_scps(ou_id, ou_node, 'OU')

            # Process child OUs
            child_ous = self.org_client.list_organizational_units_for_parent(ParentId=ou_id)['OrganizationalUnits']
            for child_ou in child_ous:
                self._traverse_ou(child_ou['Id'], ou_node)

            # Process accounts in this OU
            accounts = self.org_client.list_accounts_for_parent(ParentId=ou_id)['Accounts']
            for account in accounts:
                account_node = Node(f"Account: {account['Name']}", parent=ou_node)
                self._attach_and_save_scps(account['Id'], account_node, 'Account', include_inherited=True)

        except self.org_client.exceptions.InvalidInputException as e:
            logger.error(f"Invalid input for OU ID: {ou_id}")
            logger.error("The OU ID should follow the pattern: 'ou-' followed by 4-32 lowercase letters or digits, a dash, and 8-32 more lowercase letters or digits.")
            logger.error(f"Error details: {str(e)}")
        except Exception as e:
            logger.error(f"An error occurred while processing OU {ou_id}: {str(e)}")

    def _attach_and_save_scps(self, target_id, node, entity_type, include_inherited=False):
        try:
            attached_scps = self.org_client.list_policies_for_target(
                TargetId=target_id, Filter='SERVICE_CONTROL_POLICY')['Policies']
            node.scps = [scp['Id'] for scp in attached_scps]
            
            # Include inherited SCPs for accounts
            if include_inherited:
                inherited_scps = self._get_inherited_scps(node)
                node.all_scps = list(set(node.scps + inherited_scps))
            else:
                node.all_scps = node.scps

            # Create directory for this entity
            entity_dir = os.path.join(self.output_dir, self._get_path(node))
            os.makedirs(entity_dir, exist_ok=True)
            
            # Save SCPs
            for scp_id in node.all_scps:
                scp = self.all_scps.get(scp_id)
                if scp:
                    scp_content = self.org_client.describe_policy(PolicyId=scp_id)['Policy']['Content']
                    scp_filename = self._sanitize_filename(f"{scp['Name']}.json")
                    with open(os.path.join(entity_dir, scp_filename), 'w') as f:
                        json.dump(json.loads(scp_content), f, indent=2)
                    logger.info(f"Saved SCP {scp['Name']} for {entity_type} {node.name}")
        except Exception as e:
            logger.error(f"Error attaching and saving SCPs for {entity_type} {node.name}: {str(e)}")

    def _get_inherited_scps(self, node):
        inherited_scps = []
        current = node.parent
        while current is not None:
            if hasattr(current, 'scps'):
                inherited_scps.extend(current.scps)
            current = current.parent
        return inherited_scps

    def _get_path(self, node):
        path = []
        current = node
        while current.parent is not None:
            path.append(self._sanitize_filename(current.name))
            current = current.parent
        path.append(self._sanitize_filename(current.name))
        return os.path.join(*reversed(path))

    def _sanitize_filename(self, filename):
        return re.sub(r'[^\w\-_\. ]', '_', filename)

    def generate_report(self):
        logger.info("Generating report...")
        for pre, _, node in RenderTree(self.scp_tree):
            print(f"{pre}{node.name}")
            if hasattr(node, 'all_scps'):
                print(f"  SCPs (including inherited): {', '.join(node.all_scps)}")
            elif hasattr(node, 'scps'):
                print(f"  SCPs: {', '.join(node.scps)}")

def main():
    try:
        analyzer = SCPAnalyzer()  # Will use environment variables by default
        # Or specify a profile if needed:
        # analyzer = SCPAnalyzer('my-aws-profile')
        analyzer.map_scps_to_ous()
        analyzer.generate_report()
    except Exception as e:
        logger.error(f"An error occurred during script execution: {str(e)}")

if __name__ == "__main__":
    main()