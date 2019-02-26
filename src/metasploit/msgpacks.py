from msgpack import packb, unpackb


def unpacks(to_unpack):
  """
  Role   : Replaces the unpackb function. Unpack the message and delete bytestrings through function byte_to_string()
  Input  : The message to unpack
  Output : The unpacked message
  """
  return byte_to_string(unpackb(to_unpack, raw=True))

def byte_to_string(old_unpacked):
  """
  Role   : Recursively convert bytestrings to strings into all elements of the unpacked message
  Input  : The unpacked message with bytestrings
  Output : The unpacked message with strings only
  """
  if type(old_unpacked) is dict:
    new_unpacked = {}
    for old_key, old_value in old_unpacked.items():
      new_key=byte_to_string(old_key)
      new_unpacked[new_key]=byte_to_string(old_unpacked[old_key])

    return new_unpacked

  elif type(old_unpacked) is list:
    new_unpacked=[]
    for old_value in old_unpacked:
      new_unpacked.append(byte_to_string(old_value))

    return new_unpacked

  elif type(old_unpacked) is bytes:
    return old_unpacked.decode('utf-8')

  elif type(old_unpacked) is str or bool:
    return old_unpacked

  else:
    raise TypeError("Argument is of type {}".format(type(old_unpacked)))


def packs(to_pack):
  """
  Role   : Replaces unpackb by forcing the option 'use_bin_type=True'
  Input  : The message to pack
  Input  : The packed nessage
  """
  return packb(to_pack, use_bin_type=True)
  