from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

# تحميل النموذج من Hugging Face
model_id = "microsoft/phi-2"
tokenizer = AutoTokenizer.from_pretrained(model_id)
model = AutoModelForCausalLM.from_pretrained(model_id)

# الدالة لطرح سؤال وتحليل الإجابة
def ask_phi(question, max_tokens=200):
    inputs = tokenizer(question, return_tensors="pt")
    outputs = model.generate(**inputs, max_length=max_tokens, do_sample=True)
    return tokenizer.decode(outputs[0], skip_special_tokens=True)
