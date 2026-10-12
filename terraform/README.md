== JIMM-v3 Module ==

This is the JIMM-v3 terraform module. The idea for this module is to deploy JIMM and consume external services via offer urls.
For more information you can consult JIMM's documentation at https://canonical-jaas-documentation.readthedocs-hosted.com/en/v3

The `jimm_image` input optionally overrides the charm's `jimm-image` OCI resource with an image URL or a Charmhub resource revision. If omitted, the charm's default resource for the selected channel is used.
