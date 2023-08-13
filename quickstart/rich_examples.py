# rich library
import time

from rich.progress import Progress

# 进度条
with Progress() as progress:
    task = progress.add_task("[cyan]Processing...", total=100)
    while not progress.finished:
        progress.update(task, advance=10)
        time.sleep(0.1)

# 代码高亮
from rich.syntax import Syntax

code = """
def fibonacci(n):
    if n <= 1:
        return n
    else:
        return (fibonacci(n - 1) + fibonacci(n - 2))

for i in range(10):
    print(fibonacci(i))
"""

syntax = Syntax(code, "python", theme="monokai", line_numbers=True)
print(syntax)

# 表格
from rich.console import Console
from rich.table import Table

console = Console()

table = Table(title="Employee Information")
table.add_column("ID", style="cyan", no_wrap=True)
table.add_column("Name")
table.add_column("Position")

table.add_row("1", "John Doe", "Developer")
table.add_row("2", "Jane Smith", "Manager")

console.print(table)
