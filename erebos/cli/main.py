"""Main entry point for Erebos CLI."""

import os
import click
from erebos.cli.commands import cli


def main():
    """Main entry point with shell completion support."""
    # Enable shell completion if shell is detected
    # Click handles this automatically via the ClickGroup
    cli()


# Shell completion support for bash, zsh, fish
# Run the following to enable completion:
#   eval "$(_EREBOS_COMPLETE=bash_source erebos)"
#   eval "$(_EREBOS_COMPLETE=zsh_source erebos)"
#   eval "$(_EREBOS_COMPLETE=fish_source erebos)"
#
# For permanent installation:
#   # Bash
#   _EREBOS_COMPLETE=bash_source erebos > ~/.erebos-complete.bash
#   echo "source ~/.erebos-complete.bash" >> ~/.bashrc
#
#   # Zsh
#   _EREBOS_COMPLETE=zsh_source erebos > ~/.erebos-complete.zsh
#   echo "source ~/.erebos-complete.zsh" >> ~/.zshrc
#
#   # Fish
#   _EREBOS_COMPLETE=fish_source erebos > ~/.config/fish/completions/erebos.fish


# Auto-generate completion on import if requested
if os.environ.get("_EREBOS_COMPLETE"):
    from erebos.cli import commands as _cli_module

    _cli_module.cli()  # This will register completion


if __name__ == "__main__":
    main()
