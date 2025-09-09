from transformers import pipeline, AutoTokenizer, AutoModelForTokenClassification

model_name = 'lakshyakh93/deberta_finetuned_pii'
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForTokenClassification.from_pretrained(model_name)

# We'll use a pre-trained model fine-tuned for Named Entity Recognition.
# The "aggregation_strategy" groups parts of a single entity together (e.g., "New", "York" -> "New York").
ner_pipeline = pipeline(
    "ner", 
    model=model, 
    tokenizer=tokenizer,
    aggregation_strategy="simple"
)

# A list of entity types we consider to be potential PII from this model.
# PER (Person), LOC (Location), ORG (Organization)
# PII_ENTITY_TYPES = {"PER", "LOC", "ORG"}

CONFIDENCE_THRESHOLD = 0.95

def scan_text_for_pii(text: str) -> list[dict]:
    """
    Scans input text for PII using a specialized model and confidence threshold.
    """
    found_pii = []
    try:
        entities = ner_pipeline(text)
        
        for entity in entities:
            # Check if the entity's type is one we're looking for
            if entity.get("score") >= CONFIDENCE_THRESHOLD:
                found_pii.append(
                    {
                        "type": entity.get("entity_group"),
                        "value": entity.get("word"),
                        "score": round(entity.get("score"), 4),
                    }
                )
    except Exception as e:
        # In a real app, you'd have more robust logging
        print(f"Error during PII scan: {e}")
    
    return found_pii