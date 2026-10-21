from .cli import main

if __name__ == "__main__":  # a spawned verify worker imports this module as __mp_main__; it must not run the CLI
    main()
