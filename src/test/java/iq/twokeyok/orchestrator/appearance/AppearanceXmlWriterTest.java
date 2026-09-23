package iq.twokeyok.orchestrator.appearance;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Box;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Color;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Field;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Fields;
import iq.twokeyok.orchestrator.appearance.AppearanceTemplate.Font;
import iq.twokeyok.orchestrator.appearance.AppearanceXmlWriter.LabelOverride;

import static org.assertj.core.api.Assertions.assertThat;

class AppearanceXmlWriterTest {

    private final AppearanceXmlWriter writer = new AppearanceXmlWriter();

    private static AppearanceTemplate template() {
        Map<String, Field> fields = new LinkedHashMap<>();
        fields.put(Fields.SIGNED_BY, new Field(true, "Signed By", true, null,
                new Box(14, 5, 197, 18, null), null, null));
        fields.put(Fields.REASON, new Field(true, "Reason", true, null,
                new Box(15, 52, 226, 18, null), null, null));
        fields.put(Fields.COMPANY_LOGO, new Field(true, "Company Logo", false, null,
                new Box(274, 80, 180, 163, null), null, "logo.png"));
        return new AppearanceTemplate("t1", "Test", "A test appearance", true, 463, 250,
                new AppearanceTemplate.Border(true, new Color(1, 2, 3, null)),
                null,
                new Font("Arial", 16, new Color(0, 0, 0, null)),
                new Box(200, 450, 200, 80, 1),
                fields);
    }

    @Test
    void rendersTheAdssAppearanceDocument() {
        Map<String, String> values = new LinkedHashMap<>();
        values.put(Fields.SIGNED_BY, "John Doe");
        values.put(Fields.REASON, "Document is approved");
        values.put(Fields.COMPANY_LOGO, "aGVsbG8=");

        String xml = new String(writer.write(template(), values, Map.of()), StandardCharsets.UTF_8);

        assertThat(xml).startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>");
        assertThat(xml).contains("<SignatureAppearance discription=\"A test appearance\" height=\"250\" "
                + "name=\"t1\" width=\"463\">");
        assertThat(xml).contains("<Border showBorder=\"true\"><Color B=\"3\" G=\"2\" R=\"1\"/></Border>");
        assertThat(xml).contains("name=\"SIGNED_BY\"");
        assertThat(xml).contains("<Value>John Doe</Value>");
        assertThat(xml).contains("<Position height=\"18\" width=\"197\" x=\"14\" y=\"5\"/>");
        assertThat(xml).contains("<Font name=\"Arial\" size=\"16\">");
        // Image fields carry an ImageName and no font.
        assertThat(xml).contains("name=\"COMPANY_LOGO\"");
        assertThat(xml).contains("<ImageName>logo.png</ImageName>");
    }

    @Test
    void skipsFieldsWithoutAValue() {
        Map<String, String> values = new LinkedHashMap<>();
        values.put(Fields.SIGNED_BY, "John Doe");
        values.put(Fields.REASON, "   ");

        String xml = new String(writer.write(template(), values, Map.of()), StandardCharsets.UTF_8);

        assertThat(xml).contains("SIGNED_BY");
        assertThat(xml).doesNotContain("SIGNING_REASON");
        assertThat(xml).doesNotContain("COMPANY_LOGO");
    }

    @Test
    void escapesXmlSpecialCharacters() {
        Map<String, String> values = Map.of(Fields.SIGNED_BY, "Ali & Sons <Legal> \"Dept\"");

        String xml = new String(writer.write(template(), values, Map.of()), StandardCharsets.UTF_8);

        assertThat(xml).contains("<Value>Ali &amp; Sons &lt;Legal&gt; &quot;Dept&quot;</Value>");
    }

    @Test
    void appliesRequestLabelOverrides() {
        Map<String, String> values = Map.of(Fields.SIGNED_BY, "John Doe");
        Map<String, LabelOverride> overrides =
                Map.of(Fields.SIGNED_BY, new LabelOverride("Approved By: ", false));

        String xml = new String(writer.write(template(), values, overrides), StandardCharsets.UTF_8);

        // The trailing ": " is stripped because ADSS adds its own separator.
        assertThat(xml).contains("labelName=\"Approved By\"");
        assertThat(xml).contains("showLabel=\"false\"");
    }
}
