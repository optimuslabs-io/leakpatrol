# vhs tape for the README demo GIF.  https://github.com/charmbracelet/vhs
#
#   vhs demo.tape        # -> docs/demo.gif
#
# RECORD THIS IN A THROWAWAY VM OR CONTAINER. `make demo` generates a fixture that
# contains live indicator strings, which can trip corporate EDR on a managed
# machine. The fixture is synthetic and never committed.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 1200
Set Height 820
Set Padding 20
Set Theme "Dracula"

Type "make demo"
Sleep 500ms
Enter
Sleep 8s
Sleep 2s
