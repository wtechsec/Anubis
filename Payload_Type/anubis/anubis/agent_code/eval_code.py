    def eval_code(self, task_id, command):
        import io, sys
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            exec(compile(command, '<string>', 'exec'), {'__builtins__': __builtins__})
        finally:
            sys.stdout = old_stdout
        return buf.getvalue() or "(no output)"
