# Renders docs/demo.gif with https://github.com/charmbracelet/vhs
#   vhs docs/demo.tape
# Expects a reachable upstream. Set HOPSOCK_DEMO_HOPS to your own -F flags,
# for example:
#   export HOPSOCK_DEMO_HOPS="-F socks5://user@proxy.example.com:10001?passenv=PROXY_PASS"

Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 760
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Type `export PROXY_PASS=s3cret`
Enter
Sleep 400ms
Type `hopsock -F 'socks5://user@proxy.example.com:10001?passenv=PROXY_PASS' -F ssh://me@box.example.com`
Sleep 600ms
Hide
Ctrl+U
Type "hopsock $HOPSOCK_DEMO_HOPS -test http://ip.example.com/json"
Enter
Show
Sleep 3s
Type "b"
Sleep 1.6s
Down
Sleep 500ms
Up
Sleep 700ms
Enter
Sleep 6s
Type "v"
Sleep 3s
Type "q"
Sleep 1s
