Transport via USB HID
--------------

To get a list of KeepKeys that are currently plugged into our computer, we use the enumerate method.

.. code-block:: python

 import keepkeylib.transport_hid
 list_of_keepkey_devices = keepkeylib.transport_hid.enumerate()

We can now interact with our KeepKeys by creating a :doc:`KeepKeyClient <client>` object.

.. autoclass:: keepkeylib.transport_hid.HidTransport
  :members:
  :undoc-members: