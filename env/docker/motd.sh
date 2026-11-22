if [ -n "$PS1" ] && [ -z "$CTFKIT_MOTD_SHOWN" ]; then
  export CTFKIT_MOTD_SHOWN=1
  echo "CTFKit 完整环境"
  echo "  python3 / python  -> $(python3 --version 2>&1)"
  echo "  python2           -> $(python2 --version 2>&1)"
  echo "  pip 给 Python 3 装库；python2 -m pip 给 Python 2 装库"
  echo "  ctfkit list       列出全部工具；ctfkit-check 检查环境"
  echo "  当前目录 /work 对应启动时挂载的目录"
  echo "仅用于学习、CTF 比赛与已获授权的安全测试。"
fi
