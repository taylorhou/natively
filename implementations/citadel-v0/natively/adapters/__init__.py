"""Transport adapters. The node never sees a transport; an adapter hands it bundles
and sends what it returns. local.py runs two nodes in one process (the proof);
mail.py is the Gmail wire between citadel and Instinct (stage 1)."""
