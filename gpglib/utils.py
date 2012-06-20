def dump(bytes):
    """Return a readable string for a string of bytes"""
    r = []
    for i in range(len(bytes)):
        r.append("%02x" % ord(bytes[i]))
    return ' '.join(r)

class ValueTracker(object):
    """Track heirarchial relations of some items"""
    def __init__(self):
        self._items = {'items' : []}
        self._current = None
    
    def consumed(self, *keys, **modifiers):
        """Return list of consumed items"""
        return list(self.items(self._items, keys, modifiers))

    def start_item(self, item):
        """Record the start of an item"""
        parent = self._items
        if self._current:
            parent = self._current

        next_item = {'items' : [], 'info' : item, 'parent' : parent}
        self._current = next_item

        parent['items'].append(next_item)

    def end_item(self):
        """Record that an item was finished"""
        if self._current:
            self._current = self._current['parent']

    def items(self, items, keys, modifiers):
        """
            Get a list from the heirarchy of recorded items
            [[item, children], item, item, [item, children]]

            Where the ones of [item, children] have the same list but for it's children
        """
        if items:
            for item in items['items']:
                info = self.values_from(item['info'], keys, modifiers)
                yield info, list(self.items(item, keys, modifiers))
    
    def values_from(self, info, keys, modifiers):
        """Extract wanted information from info"""
        # Return info if we don't want to get anything from it
        if not keys and not modifiers:
            return info
        
        # We want to get things from info
        result = {}
        for key in (list(keys) + modifiers.keys()):
            if type(info) is dict:
                val = info[key]
            else:
                val = getattr(info, key)
            result[key] = val
        for key, modifier in modifiers.items():
            result[key] = modifier(info, key, val)
        
        if not modifiers and len(keys) == 1:
            key = keys[0]
            return result[key]
        
        if not keys and len(modifiers) == 1:
            key = modifiers.keys()[0]
            return result[key]
        
        return result
