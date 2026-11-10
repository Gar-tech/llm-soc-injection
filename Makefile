.PHONY: demo real-anthropic real-ollama plot clean

# Offline, no API key: synthetic data + mock classifier. Proves the pipeline runs.
demo:
	cd src && python3 make_demo_data.py
	cd src && python3 run_experiment.py --reports ../data/reports --labels ../data/labels.csv --backend mock
	cd src && python3 plot_results.py

# Real numbers with Claude. Needs ANTHROPIC_API_KEY and `pip install anthropic`.
# Point --reports/--labels at the real Avast-CTU reports you downloaded.
real-anthropic:
	cd src && python3 run_experiment.py --reports ../data/reports --labels ../data/labels.csv \
		--backend anthropic --model claude-sonnet-4-6 --sleep 0.3
	cd src && python3 plot_results.py

# Real numbers with a local Ollama (free, no key). Start `ollama serve` first.
real-ollama:
	OPENAI_BASE_URL=http://localhost:11434/v1 OPENAI_API_KEY=ollama \
	  python3 src/run_experiment.py --reports data/reports --labels data/labels.csv \
	  --backend openai --model llama3.1:8b
	python3 src/plot_results.py

plot:
	cd src && python3 plot_results.py

clean:
	rm -rf data/reports data/labels.csv results/*.csv results/*.json figures/*.png
