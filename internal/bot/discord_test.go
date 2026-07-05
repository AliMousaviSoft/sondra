package bot

import (
	"testing"

	"github.com/bwmarrin/discordgo"
)

func TestCommandFromInteractionScan(t *testing.T) {
	data := discordgo.ApplicationCommandInteractionData{
		Name: "scan",
		Options: []*discordgo.ApplicationCommandInteractionDataOption{
			{Name: "domain", Type: discordgo.ApplicationCommandOptionString, Value: "Example.com"},
			{Name: "preset", Type: discordgo.ApplicationCommandOptionString, Value: "full"},
			{Name: "modules", Type: discordgo.ApplicationCommandOptionString, Value: "subfinder,httpx"},
			{Name: "exclude", Type: discordgo.ApplicationCommandOptionString, Value: "dev.example.com"},
		},
	}
	c := commandFromInteraction(data)
	if c.Name != "scan" || c.Domain != "example.com" || c.Preset != "full" {
		t.Fatalf("got %+v", c)
	}
	if len(c.Modules) != 2 || c.Modules[0] != "subfinder" {
		t.Fatalf("modules: %v", c.Modules)
	}
	if len(c.Exclude) != 1 || c.Exclude[0] != "dev.example.com" {
		t.Fatalf("exclude: %v", c.Exclude)
	}
}

func TestCommandFromInteractionStop(t *testing.T) {
	data := discordgo.ApplicationCommandInteractionData{
		Name: "stop",
		Options: []*discordgo.ApplicationCommandInteractionDataOption{
			{Name: "id", Type: discordgo.ApplicationCommandOptionInteger, Value: float64(3)},
		},
	}
	c := commandFromInteraction(data)
	if c.Name != "stop" || c.Arg != "3" {
		t.Fatalf("got %+v", c)
	}
}

func TestSlashCommandsWellFormed(t *testing.T) {
	for _, c := range slashCommands() {
		if c.Name == "" || c.Description == "" {
			t.Fatalf("command missing name/description: %+v", c)
		}
		// Discord requires required options before optional ones.
		seenOptional := false
		for _, o := range c.Options {
			if o.Required {
				if seenOptional {
					t.Fatalf("%s: required option %q after an optional one", c.Name, o.Name)
				}
			} else {
				seenOptional = true
			}
		}
	}
}
