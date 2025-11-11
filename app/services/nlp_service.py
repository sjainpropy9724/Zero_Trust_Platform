from transformers import pipeline, AutoTokenizer, AutoModelForTokenClassification

model_name = 'lakshyakh93/deberta_finetuned_pii'
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForTokenClassification.from_pretrained(model_name)

ner_pipeline = pipeline(
    "ner", 
    model=model, 
    tokenizer=tokenizer,
    aggregation_strategy="simple"
)

CONFIDENCE_THRESHOLD = 0.95

def scan_text_for_pii(text: str) -> list[dict]:
    """
    Scans input text for PII using a specialized model and confidence threshold.
    """
    found_pii = []
    try:
        entities = ner_pipeline(text)
        
        for entity in entities:
            if entity.get("score") >= CONFIDENCE_THRESHOLD:
                found_pii.append(
                    {
                        "type": entity.get("entity_group"),
                        "value": entity.get("word"),
                        "score": round(entity.get("score"), 4),
                    }
                )
    except Exception as e:
        print(f"Error during PII scan: {e}")
    
    return found_pii