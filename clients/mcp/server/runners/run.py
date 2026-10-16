import ast, asyncio, inspect, linecache, sys
sys.path.insert(0, '')
src = open('.plimsoll/cell.py', encoding='utf-8').read()
linecache.cache['cell'] = (len(src), None, src.splitlines(True), 'cell')
tree = ast.parse(src, 'cell', 'exec')
last = ast.Expression(tree.body.pop().value) if tree.body and isinstance(tree.body[-1], ast.Expr) else None
ns = {'__name__': '__main__', '__builtins__': __builtins__}
flags = ast.PyCF_ALLOW_TOP_LEVEL_AWAIT
loop = asyncio.new_event_loop()
def settle(r):
    return loop.run_until_complete(r) if inspect.isawaitable(r) else r
settle(eval(compile(tree, 'cell', 'exec', flags=flags), ns))
if last is not None:
    value = settle(eval(compile(last, 'cell', 'eval', flags=flags), ns))
    if value is not None:
        print(repr(value))
