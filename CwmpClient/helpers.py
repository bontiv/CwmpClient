from CwmpClient.nodes import BaseNode


def prettyprint(tree, prefix = ""):
    for elem in tree:
        if isinstance(tree[elem], BaseNode):
            prettyprint(tree[elem], prefix + '.' + elem if len(prefix) > 0 else elem)
        else:
            print(prefix + '.' + elem + ' = ' + str(tree[elem]))