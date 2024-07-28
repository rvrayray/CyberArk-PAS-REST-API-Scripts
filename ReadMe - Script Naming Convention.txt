Script naming convention

function-of-the-script-authentication-type-script-type(interactive or not)

Examples:

1. add-safe-add-safe-members-ldap-interactive.ps1
	This script will add a new safe and add safe members to that safe. The script will prompt the user to input the safe name and the Active Directory group to be added as safe members. The script will authenticate via LDAP and is user interactive.

2. get-pwd-value-pki.ps1
	This script will retrieve the password value for the account ID that is hardcoded within the script. The script authenticates via PKI and is not user interactive.

3. get-acct-pwd-ldap-interactive.ps1
	This script will retrieve the password value for the account ID the user inputs when prompted by the script. The script authenticates via LDAP and is user interactive.

4. generate-pwd-set-next-pwd-ldap-interactive.ps1
	This script will generate a new password and then set that password as the next password for the account ID that the user inputs when prompted by the script. The script authenticates via LDAP and is user interactive.
