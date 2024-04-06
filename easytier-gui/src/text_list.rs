#[derive(Default)]
pub struct TextListOption {
    pub hint: String,
}

pub fn text_list_ui(
    ui: &mut egui::Ui,
    id: &str,
    texts: &mut Vec<String>,
    option: Option<TextListOption>,
) {
    let option = option.unwrap_or_default();
    // convert text vec to (index, text) vec
    let mut add_new_item = false;
    let mut remove_idxs = vec![];

    egui::Grid::new(id).max_col_width(200.0).show(ui, |ui| {
        for i in 0..texts.len() {
            egui::TextEdit::singleline(&mut texts[i])
                .hint_text(&option.hint)
                .show(ui);

            ui.horizontal(|ui| {
                if ui.button("➖").clicked() {
                    remove_idxs.push(i);
                }

                if i == texts.len() - 1 {
                    if ui.button("➕").clicked() {
                        add_new_item = true;
                    }
                }
            });

            ui.end_row();
        }

        if texts.len() == 0 {
            if ui.button("➕").clicked() {
                add_new_item = true;
            }
            ui.end_row();
        }
    });

    let new_texts = texts
        .iter()
        .enumerate()
        .filter(|(i, _)| !remove_idxs.contains(i))
        .map(|(_, t)| t.clone())
        .collect::<Vec<String>>();
    *texts = new_texts;

    if add_new_item && texts.last().map(|t| !t.is_empty()).unwrap_or(true) {
        texts.push("".to_string());
    }
}
