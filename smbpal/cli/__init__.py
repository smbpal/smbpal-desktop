"""The command line client.

Built before the GUI on purpose: it forces the IPC boundary to be real rather
than a function call the GUI could reach around. If this is awkward to use, the
protocol is wrong, and here is much the cheaper place to find that out.
"""
